// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http/httpguts"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netutil"
	"tailscale.com/net/sockstats"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/wgengine/filter"
)

var initListenConfig func(*net.ListenConfig, netip.Addr, *netmon.State, string) error

// peerDNSQueryHandler is implemented by tsdns.Resolver.
type peerDNSQueryHandler interface {
	HandlePeerDNSQuery(context.Context, []byte, netip.AddrPort, func(name string) bool) (res []byte, err error)
}

type peerAPIServer struct {
	b        *LocalBackend
	resolver peerDNSQueryHandler
}

func (s *peerAPIServer) listen(ip netip.Addr, ifState *netmon.State) (ln net.Listener, err error) {
	// Android for whatever reason often has problems creating the peerapi listener.
	// But since we started intercepting it with netstack, it's not even important that
	// we have a real kernel-level listener. So just create a dummy listener on Android
	// and let netstack intercept it.
	if runtime.GOOS == "android" {
		return newFakePeerAPIListener(ip), nil
	}

	ipStr := ip.String()

	var lc net.ListenConfig
	if initListenConfig != nil {
		// On iOS/macOS, this sets the lc.Control hook to
		// setsockopt the interface index to bind to, to get
		// out of the network sandbox.
		if err := initListenConfig(&lc, ip, ifState, s.b.dialer.TUNName()); err != nil {
			return nil, err
		}
		if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
			ipStr = ""
		}
	}

	if s.b.sys.IsNetstack() {
		ipStr = ""
	}

	tcp4or6 := "tcp4"
	if ip.Is6() {
		tcp4or6 = "tcp6"
	}

	// Make a best effort to pick a deterministic port number for
	// the ip. The lower three bytes are the same for IPv4 and IPv6
	// Tailscale addresses (at least currently), so we'll usually
	// get the same port number on both address families for
	// dev/debugging purposes, which is nice. But it's not so
	// deterministic that people will bake this into clients.
	// We try a few times just in case something's already
	// listening on that port (on all interfaces, probably).
	for try := uint8(0); try < 5; try++ {
		a16 := ip.As16()
		hashData := a16[len(a16)-3:]
		hashData[0] += try
		tryPort := (32 << 10) | uint16(crc32.ChecksumIEEE(hashData))
		ln, err = lc.Listen(context.Background(), tcp4or6, net.JoinHostPort(ipStr, strconv.Itoa(int(tryPort))))
		if err == nil {
			return ln, nil
		}
	}
	// Fall back to some random ephemeral port.
	ln, err = lc.Listen(context.Background(), tcp4or6, net.JoinHostPort(ipStr, "0"))

	// And if we're on a platform with netstack (anything but iOS), then just fallback to netstack.
	if err != nil && runtime.GOOS != "ios" {
		s.b.logf("peerapi: failed to do peerAPI listen, harmless (netstack available) but error was: %v", err)
		return newFakePeerAPIListener(ip), nil
	}
	return ln, err
}

type peerAPIListener struct {
	ps *peerAPIServer
	ip netip.Addr
	lb *LocalBackend

	// ln is the Listener. It can be nil in netstack mode if there are more than
	// 1 local addresses (e.g. both an IPv4 and IPv6). When it's nil, port
	// and urlStr are still populated.
	ln net.Listener

	// urlStr is the base URL to access the PeerAPI (http://ip:port/).
	urlStr string
	// port is just the port of urlStr.
	port int
}

func (pln *peerAPIListener) Close() error {
	if !buildfeatures.HasPeerAPIServer {
		return nil
	}
	if pln.ln != nil {
		return pln.ln.Close()
	}
	return nil
}

func (pln *peerAPIListener) serve() {
	if !buildfeatures.HasPeerAPIServer {
		return
	}
	if pln.ln == nil {
		return
	}
	defer pln.ln.Close()
	logf := pln.lb.logf
	for {
		c, err := pln.ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			logf("peerapi.Accept: %v", err)
			return
		}
		ta, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok {
			c.Close()
			logf("peerapi: unexpected RemoteAddr %#v", c.RemoteAddr())
			continue
		}
		ipp := netaddr.Unmap(ta.AddrPort())
		if !ipp.IsValid() {
			logf("peerapi: bogus TCPAddr %#v", ta)
			c.Close()
			continue
		}
		pln.ServeConn(ipp, c)
	}
}

func (pln *peerAPIListener) ServeConn(src netip.AddrPort, c net.Conn) {
	logf := pln.lb.logf
	peerNode, peerUser, ok := pln.lb.WhoIs("tcp", src)
	if !ok {
		logf("peerapi: unknown peer %v", src)
		c.Close()
		return
	}
	nm := pln.lb.NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		logf("peerapi: no netmap")
		c.Close()
		return
	}
	h := &peerAPIHandler{
		ps:         pln.ps,
		isSelf:     nm.SelfNode.User() == peerNode.User(),
		remoteAddr: src,
		selfNode:   nm.SelfNode,
		peerNode:   peerNode,
		peerUser:   peerUser,
	}
	httpServer := &http.Server{
		Handler:   h,
		Protocols: new(http.Protocols),
	}
	httpServer.Protocols.SetHTTP1(true)
	httpServer.Protocols.SetUnencryptedHTTP2(true) // over WireGuard; "unencrypted" means no TLS
	go httpServer.Serve(netutil.NewOneConnListener(c, nil))
}

// peerAPIHandler serves the PeerAPI for a source specific client.
type peerAPIHandler struct {
	ps         *peerAPIServer
	remoteAddr netip.AddrPort
	isSelf     bool                // whether peerNode is owned by same user as this node
	selfNode   tailcfg.NodeView    // this node; always non-nil
	peerNode   tailcfg.NodeView    // peerNode is who's making the request
	peerUser   tailcfg.UserProfile // profile of peerNode
}

// PeerAPIHandler is the interface implemented by [peerAPIHandler] and needed by
// module features registered via tailscale.com/feature/*.
type PeerAPIHandler interface {
	Peer() tailcfg.NodeView
	PeerCaps() tailcfg.PeerCapMap
	CanDebug() bool // can remote node can debug this node (internal state, etc)
	Self() tailcfg.NodeView
	LocalBackend() *LocalBackend
	IsSelfUntagged() bool // whether the peer is untagged and the same as this user
	RemoteAddr() netip.AddrPort
	Logf(format string, a ...any)
}

func (h *peerAPIHandler) IsSelfUntagged() bool {
	return !h.selfNode.IsTagged() && !h.peerNode.IsTagged() && h.isSelf
}
func (h *peerAPIHandler) Peer() tailcfg.NodeView      { return h.peerNode }
func (h *peerAPIHandler) Self() tailcfg.NodeView      { return h.selfNode }
func (h *peerAPIHandler) RemoteAddr() netip.AddrPort  { return h.remoteAddr }
func (h *peerAPIHandler) LocalBackend() *LocalBackend { return h.ps.b }
func (h *peerAPIHandler) Logf(format string, a ...any) {
	h.logf(format, a...)
}

func (h *peerAPIHandler) logf(format string, a ...any) {
	h.ps.b.logf("peerapi: "+format, a...)
}

func (h *peerAPIHandler) logfv1(format string, a ...any) {
	h.ps.b.logf("[v1] peerapi: "+format, a...)
}

// isAddressValid reports whether addr is a valid destination address for this
// node originating from the peer.
func (h *peerAPIHandler) isAddressValid(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	v4MasqAddr, hasMasqV4 := h.peerNode.SelfNodeV4MasqAddrForThisPeer().GetOk()
	v6MasqAddr, hasMasqV6 := h.peerNode.SelfNodeV6MasqAddrForThisPeer().GetOk()
	if hasMasqV4 || hasMasqV6 {
		return addr == v4MasqAddr || addr == v6MasqAddr
	}
	pfx := netip.PrefixFrom(addr, addr.BitLen())
	return views.SliceContains(h.selfNode.Addresses(), pfx)
}

func (h *peerAPIHandler) validateHost(r *http.Request) error {
	if r.Host == "peer" {
		return nil
	}
	ap, err := netip.ParseAddrPort(r.Host)
	if err != nil {
		return err
	}
	if !h.isAddressValid(ap.Addr()) {
		return fmt.Errorf("%v not found in self addresses", ap.Addr())
	}
	return nil
}

func (h *peerAPIHandler) validatePeerAPIRequest(r *http.Request) error {
	if r.Referer() != "" {
		return errors.New("unexpected Referer")
	}
	if r.Header.Get("Origin") != "" {
		return errors.New("unexpected Origin")
	}
	return h.validateHost(r)
}

// peerAPIRequestShouldGetSecurityHeaders reports whether the PeerAPI request r
// should get security response headers. It aims to report true for any request
// from a browser and false for requests from tailscaled (Go) clients.
//
// PeerAPI is primarily an RPC mechanism between Tailscale instances. Some of
// the HTTP handlers are useful for debugging with curl or browsers, but in
// general the client is always tailscaled itself. Because PeerAPI only uses
// HTTP/1 without HTTP/2 and its HPACK helping with repetitive headers, we try
// to minimize header bytes sent in the common case when the client isn't a
// browser. Minimizing bytes is important in particular with the ExitDNS service
// provided by exit nodes, processing DNS clients from queries. We don't want to
// waste bytes with security headers to non-browser clients. But if there's any
// hint that the request is from a browser, then we do.
func peerAPIRequestShouldGetSecurityHeaders(r *http.Request) bool {
	// Accept-Encoding is a forbidden header
	// (https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name)
	// that Chrome, Firefox, Safari, etc send, but Go does not. So if we see it,
	// it's probably a browser and not a Tailscale PeerAPI (Go) client.
	if httpguts.HeaderValuesContainsToken(r.Header["Accept-Encoding"], "deflate") {
		return true
	}
	// Clients can mess with their User-Agent, but if they say Mozilla or have a bunch
	// of components (spaces) they're likely a browser.
	if ua := r.Header.Get("User-Agent"); strings.HasPrefix(ua, "Mozilla/") || strings.Count(ua, " ") > 2 {
		return true
	}
	// Tailscale/PeerAPI/Go clients don't have an Accept-Language.
	if r.Header.Get("Accept-Language") != "" {
		return true
	}
	return false
}

// RegisterPeerAPIHandler registers a PeerAPI handler.
//
// The path should be of the form "/v0/foo".
//
// It panics if the path is already registered.
func RegisterPeerAPIHandler(path string, f func(PeerAPIHandler, http.ResponseWriter, *http.Request)) {
	if !buildfeatures.HasPeerAPIServer {
		return
	}
	if _, ok := peerAPIHandlers[path]; ok {
		panic(fmt.Sprintf("duplicate PeerAPI handler %q", path))
	}
	peerAPIHandlers[path] = f
	if strings.HasSuffix(path, "/") {
		peerAPIHandlerPrefixes[path] = f
	}
}

var (
	peerAPIHandlers = map[string]func(PeerAPIHandler, http.ResponseWriter, *http.Request){} // by URL.Path

	// peerAPIHandlerPrefixes are the subset of peerAPIHandlers where
	// the map key ends with a slash, indicating a prefix match.
	peerAPIHandlerPrefixes = map[string]func(PeerAPIHandler, http.ResponseWriter, *http.Request){}
)

func (h *peerAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasPeerAPIServer {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	if err := h.validatePeerAPIRequest(r); err != nil {
		metricInvalidRequests.Add(1)
		h.logf("invalid request from %v: %v", h.remoteAddr, err)
		http.Error(w, "invalid peerapi request", http.StatusForbidden)
		return
	}
	if peerAPIRequestShouldGetSecurityHeaders(r) {
		w.Header().Set("Content-Security-Policy", `default-src 'none'; frame-ancestors 'none'; script-src 'none'; script-src-elem 'none'; script-src-attr 'none'; style-src 'unsafe-inline'`)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	for pfx, ph := range peerAPIHandlerPrefixes {
		if strings.HasPrefix(r.URL.Path, pfx) {
			ph(h, w, r)
			return
		}
	}
	if buildfeatures.HasDNS && strings.HasPrefix(r.URL.Path, "/dns-query") {
		metricDNSCalls.Add(1)
		h.handleDNSQuery(w, r)
		return
	}
	if buildfeatures.HasDebug {
		switch r.URL.Path {
		case "/v0/goroutines":
			h.handleServeGoroutines(w, r)
			return
		case "/v0/env":
			h.handleServeEnv(w, r)
			return
		case "/v0/metrics":
			h.handleServeMetrics(w, r)
			return
		case "/v0/magicsock":
			h.handleServeMagicsock(w, r)
			return
		case "/v0/dnsfwd":
			h.handleServeDNSFwd(w, r)
			return
		case "/v0/interfaces":
			h.handleServeInterfaces(w, r)
			return
		case "/v0/sockstats":
			h.handleServeSockStats(w, r)
			return
		}
	}
	if ph, ok := peerAPIHandlers[r.URL.Path]; ok {
		ph(h, w, r)
		return
	}
	if r.URL.Path != "/" {
		http.Error(w, "unsupported peerapi path", http.StatusNotFound)
		return
	}
	who := h.peerUser.DisplayName
	fmt.Fprintf(w, `<html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<body>
<h1>Hello, %s (%v)</h1>
This is my Tailscale device. Your device is %v.
`, html.EscapeString(who), h.remoteAddr.Addr(), html.EscapeString(h.peerNode.ComputedName()))

	if h.isSelf {
		fmt.Fprintf(w, "<p>You are the owner of this node.\n")
	}
}

func (h *peerAPIHandler) handleServeInterfaces(w http.ResponseWriter, r *http.Request) {
	if !h.canDebug() {
		http.Error(w, "denied; no debug access", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintln(w, "<h1>Interfaces</h1>")

	if dr, err := netmon.DefaultRoute(); err == nil {
		fmt.Fprintf(w, "<h3>Default route is %q(%d)</h3>\n", html.EscapeString(dr.InterfaceName), dr.InterfaceIndex)
	} else {
		fmt.Fprintf(w, "<h3>Could not get the default route: %s</h3>\n", html.EscapeString(err.Error()))
	}

	if hasCGNATInterface, err := h.ps.b.sys.NetMon.Get().HasCGNATInterface(); hasCGNATInterface {
		fmt.Fprintln(w, "<p>There is another interface using the CGNAT range.</p>")
	} else if err != nil {
		fmt.Fprintf(w, "<p>Could not check for CGNAT interfaces: %s</p>\n", html.EscapeString(err.Error()))
	}

	i, err := netmon.GetInterfaceList()
	if err != nil {
		fmt.Fprintf(w, "Could not get interfaces: %s\n", html.EscapeString(err.Error()))
		return
	}

	fmt.Fprintln(w, "<table style='border-collapse: collapse' border=1 cellspacing=0 cellpadding=2>")
	fmt.Fprint(w, "<tr>")
	for _, v := range []any{"Index", "Name", "MTU", "Flags", "Addrs", "Extra"} {
		fmt.Fprintf(w, "<th>%v</th> ", v)
	}
	fmt.Fprint(w, "</tr>\n")
	i.ForeachInterface(func(iface netmon.Interface, ipps []netip.Prefix) {
		fmt.Fprint(w, "<tr>")
		for _, v := range []any{iface.Index, iface.Name, iface.MTU, iface.Flags, ipps} {
			fmt.Fprintf(w, "<td>%s</td> ", html.EscapeString(fmt.Sprintf("%v", v)))
		}
		if extras, err := netmon.InterfaceDebugExtras(iface.Index); err == nil && extras != "" {
			fmt.Fprintf(w, "<td>%s</td> ", html.EscapeString(extras))
		} else if err != nil {
			fmt.Fprintf(w, "<td>%s</td> ", html.EscapeString(err.Error()))
		}
		fmt.Fprint(w, "</tr>\n")
	})
	fmt.Fprintln(w, "</table>")
}

func (h *peerAPIHandler) handleServeSockStats(w http.ResponseWriter, r *http.Request) {
	if !h.canDebug() {
		http.Error(w, "denied; no debug access", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintln(w, "<!DOCTYPE html><h1>Socket Stats</h1>")

	if !sockstats.IsAvailable {
		fmt.Fprintln(w, "Socket stats are not available for this client")
		return
	}

	stats, interfaceStats, validation := sockstats.Get(), sockstats.GetInterfaces(), sockstats.GetValidation()
	if stats == nil {
		fmt.Fprintln(w, "No socket stats available")
		return
	}

	fmt.Fprintln(w, "<table border='1' cellspacing='0' style='border-collapse: collapse;'>")
	fmt.Fprintln(w, "<thead>")
	fmt.Fprintln(w, "<th>Label</th>")
	fmt.Fprintln(w, "<th>Tx</th>")
	fmt.Fprintln(w, "<th>Rx</th>")
	for _, iface := range interfaceStats.Interfaces {
		fmt.Fprintf(w, "<th>Tx (%s)</th>", html.EscapeString(iface))
		fmt.Fprintf(w, "<th>Rx (%s)</th>", html.EscapeString(iface))
	}
	fmt.Fprintln(w, "<th>Validation</th>")
	fmt.Fprintln(w, "</thead>")

	fmt.Fprintln(w, "<tbody>")
	labels := make([]sockstats.Label, 0, len(stats.Stats))
	for label := range stats.Stats {
		labels = append(labels, label)
	}
	slices.SortFunc(labels, func(a, b sockstats.Label) int {
		return strings.Compare(a.String(), b.String())
	})

	txTotal := uint64(0)
	rxTotal := uint64(0)
	txTotalByInterface := map[string]uint64{}
	rxTotalByInterface := map[string]uint64{}

	for _, label := range labels {
		stat := stats.Stats[label]
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, "<td>%s</td>", html.EscapeString(label.String()))
		fmt.Fprintf(w, "<td align=right>%d</td>", stat.TxBytes)
		fmt.Fprintf(w, "<td align=right>%d</td>", stat.RxBytes)

		txTotal += stat.TxBytes
		rxTotal += stat.RxBytes

		if interfaceStat, ok := interfaceStats.Stats[label]; ok {
			for _, iface := range interfaceStats.Interfaces {
				fmt.Fprintf(w, "<td align=right>%d</td>", interfaceStat.TxBytesByInterface[iface])
				fmt.Fprintf(w, "<td align=right>%d</td>", interfaceStat.RxBytesByInterface[iface])
				txTotalByInterface[iface] += interfaceStat.TxBytesByInterface[iface]
				rxTotalByInterface[iface] += interfaceStat.RxBytesByInterface[iface]
			}
		}

		if validationStat, ok := validation.Stats[label]; ok && (validationStat.RxBytes > 0 || validationStat.TxBytes > 0) {
			fmt.Fprintf(w, "<td>Tx=%d (%+d) Rx=%d (%+d)</td>",
				validationStat.TxBytes,
				int64(validationStat.TxBytes)-int64(stat.TxBytes),
				validationStat.RxBytes,
				int64(validationStat.RxBytes)-int64(stat.RxBytes))
		} else {
			fmt.Fprintln(w, "<td></td>")
		}

		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody>")

	fmt.Fprintln(w, "<tfoot>")
	fmt.Fprintln(w, "<th>Total</th>")
	fmt.Fprintf(w, "<th>%d</th>", txTotal)
	fmt.Fprintf(w, "<th>%d</th>", rxTotal)
	for _, iface := range interfaceStats.Interfaces {
		fmt.Fprintf(w, "<th>%d</th>", txTotalByInterface[iface])
		fmt.Fprintf(w, "<th>%d</th>", rxTotalByInterface[iface])
	}
	fmt.Fprintln(w, "<th></th>")
	fmt.Fprintln(w, "</tfoot>")

	fmt.Fprintln(w, "</table>")

	fmt.Fprintln(w, "<h2>Debug Info</h2>")

	fmt.Fprintln(w, "<pre>")
	fmt.Fprintln(w, html.EscapeString(sockstats.DebugInfo()))
	fmt.Fprintln(w, "</pre>")
}

func (h *peerAPIHandler) CanDebug() bool { return h.canDebug() }

// canDebug reports whether h can debug this node (goroutines, metrics,
// magicsock internal state, etc).
func (h *peerAPIHandler) canDebug() bool {
	if !h.selfNode.HasCap(tailcfg.CapabilityDebug) {
		// This node does not expose debug info.
		return false
	}
	if h.peerNode.UnsignedPeerAPIOnly() {
		// Unsigned peers can't debug.
		return false
	}
	return h.isSelf || h.peerHasCap(tailcfg.PeerCapabilityDebugPeer)
}

var allowSelfIngress = envknob.RegisterBool("TS_ALLOW_SELF_INGRESS")

// canIngress reports whether h can send ingress requests to this node.
func (h *peerAPIHandler) canIngress() bool {
	return h.peerHasCap(tailcfg.PeerCapabilityIngress) || (allowSelfIngress() && h.isSelf)
}

func (h *peerAPIHandler) peerHasCap(wantCap tailcfg.PeerCapability) bool {
	return h.PeerCaps().HasCapability(wantCap)
}

func (h *peerAPIHandler) PeerCaps() tailcfg.PeerCapMap {
	return h.ps.b.PeerCaps(h.remoteAddr.Addr())
}

func (h *peerAPIHandler) handleServeGoroutines(w http.ResponseWriter, r *http.Request) {
	if !h.canDebug() {
		http.Error(w, "denied; no debug access", http.StatusForbidden)
		return
	}
	var buf []byte
	for size := 4 << 10; size <= 2<<20; size *= 2 {
		buf = make([]byte, size)
		buf = buf[:runtime.Stack(buf, true)]
		if len(buf) < size {
			break
		}
	}
	w.Write(buf)
}

func (h *peerAPIHandler) handleServeEnv(w http.ResponseWriter, r *http.Request) {
	if !h.canDebug() {
		http.Error(w, "denied; no debug access", http.StatusForbidden)
		return
	}
	var data struct {
		Hostinfo *tailcfg.Hostinfo
		Uid      int
		Args     []string
		Env      []string
	}
	data.Hostinfo = hostinfo.New()
	data.Uid = os.Getuid()
	data.Args = os.Args
	data.Env = os.Environ()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (h *peerAPIHandler) handleServeMagicsock(w http.ResponseWriter, r *http.Request) {
	if !h.canDebug() {
		http.Error(w, "denied; no debug access", http.StatusForbidden)
		return
	}
	h.ps.b.MagicConn().ServeHTTPDebug(w, r)
}

func (h *peerAPIHandler) handleServeMetrics(w http.ResponseWriter, r *http.Request) {
	if !h.canDebug() {
		http.Error(w, "denied; no debug access", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	clientmetric.WritePrometheusExpositionFormat(w)
}

func (h *peerAPIHandler) handleServeDNSFwd(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDNS {
		http.NotFound(w, r)
		return
	}
	if !h.canDebug() {
		http.Error(w, "denied; no debug access", http.StatusForbidden)
		return
	}
	dh := health.DebugHandler("dnsfwd")
	if dh == nil {
		http.Error(w, "not wired up", http.StatusInternalServerError)
		return
	}
	dh.ServeHTTP(w, r)
}

func (h *peerAPIHandler) replyToDNSQueries() bool {
	if !buildfeatures.HasDNS {
		return false
	}
	if h.isSelf {
		// If the peer is owned by the same user, just allow it
		// without further checks.
		return true
	}
	b := h.ps.b
	if !b.OfferingExitNode() && !b.OfferingAppConnector() {
		// If we're not an exit node or app connector, there's
		// no point to being a DNS server for somebody.
		return false
	}
	if !h.remoteAddr.IsValid() {
		// This should never be the case if the peerAPIHandler
		// was wired up correctly, but just in case.
		return false
	}
	// Otherwise, we're an exit node but the peer is not us, so
	// we need to check if they're allowed access to the internet.
	// As peerapi bypasses wgengine/filter checks, we need to check
	// ourselves. As a proxy for autogroup:internet access, we see
	// if we would've accepted a packet to 0.0.0.0:53. We treat
	// the IP 0.0.0.0 as being "the internet".
	//
	// Because of the way that filter checks work, rules are only
	// checked after ensuring the destination IP is part of the
	// local set of IPs. An exit node has 0.0.0.0/0 so its fine,
	// but an app connector explicitly adds 0.0.0.0/32 (and the
	// IPv6 equivalent) to make this work (see updateFilterLocked
	// in LocalBackend).
	f := b.currentNode().filter()
	if f == nil {
		return false
	}
	// Note: we check TCP here because the Filter type already had
	// a CheckTCP method (for unit tests), but it's pretty
	// arbitrary. DNS runs over TCP and UDP, so sure... we check
	// TCP.
	dstIP := netaddr.IPv4(0, 0, 0, 0)
	remoteIP := h.remoteAddr.Addr()
	if remoteIP.Is6() {
		// autogroup:internet for IPv6 is defined to start with 2000::/3,
		// so use 2000::0 as the probe "the internet" address.
		dstIP = netip.MustParseAddr("2000::")
	}
	verdict := f.CheckTCP(remoteIP, dstIP, 53)
	return verdict == filter.Accept
}

// handleDNSQuery implements a DoH server (RFC 8484) over the peerapi.
// It's not over HTTPS as the spec dictates, but rather HTTP-over-WireGuard.
func (h *peerAPIHandler) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDNS || h.ps.resolver == nil {
		http.Error(w, "DNS not wired up", http.StatusNotImplemented)
		return
	}
	if !h.replyToDNSQueries() {
		http.Error(w, "DNS access denied", http.StatusForbidden)
		return
	}
	pretty := false // non-DoH debug mode for humans
	q, publicError := dohQuery(r)
	if publicError != "" && r.Method == "GET" {
		if name := r.FormValue("q"); name != "" {
			pretty = true
			publicError = ""
			q = dnsQueryForName(name, r.FormValue("t"))
		}
	}
	if publicError != "" {
		http.Error(w, publicError, http.StatusBadRequest)
		return
	}

	// Some timeout that's short enough to be noticed by humans
	// but long enough that it's longer than real DNS timeouts.
	const arbitraryTimeout = 5 * time.Second

	ctx, cancel := context.WithTimeout(r.Context(), arbitraryTimeout)
	defer cancel()
	res, err := h.ps.resolver.HandlePeerDNSQuery(ctx, q, h.remoteAddr, h.ps.b.allowExitNodeDNSProxyToServeName)
	if err != nil {
		h.logf("handleDNS fwd error: %v", err)
		if err := ctx.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			http.Error(w, "DNS forwarding error", http.StatusInternalServerError)
		}
		return
	}
	// TODO(raggi): consider pushing the integration down into the resolver
	// instead to avoid re-parsing the DNS response for improved performance in
	// the future.
	if buildfeatures.HasAppConnectors && h.ps.b.OfferingAppConnector() {
		if err := h.ps.b.ObserveDNSResponse(res); err != nil {
			h.logf("ObserveDNSResponse error: %v", err)
			// This is not fatal, we probably just failed to parse the upstream
			// response. Return it to the caller anyway.
		}
	}

	if pretty {
		// Non-standard response for interactive debugging.
		w.Header().Set("Content-Type", "application/json")
		writePrettyDNSReply(w, res)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", strconv.Itoa(len(res)))
	w.Write(res)
}

func dohQuery(r *http.Request) (dnsQuery []byte, publicErr string) {
	const maxQueryLen = 256 << 10
	switch r.Method {
	default:
		return nil, "bad HTTP method"
	case "GET":
		q64 := r.FormValue("dns")
		if q64 == "" {
			return nil, "missing ‘dns’ parameter; try '?dns=' (DoH standard) or use '?q=<name>' for JSON debug mode"
		}
		if base64.RawURLEncoding.DecodedLen(len(q64)) > maxQueryLen {
			return nil, "query too large"
		}
		q, err := base64.RawURLEncoding.DecodeString(q64)
		if err != nil {
			return nil, "invalid 'dns' base64 encoding"
		}
		return q, ""
	case "POST":
		if r.Header.Get("Content-Type") != "application/dns-message" {
			return nil, "unexpected Content-Type"
		}
		q, err := io.ReadAll(io.LimitReader(r.Body, maxQueryLen+1))
		if err != nil {
			return nil, "error reading post body with DNS query"
		}
		if len(q) > maxQueryLen {
			return nil, "query too large"
		}
		return q, ""
	}
}

func dnsQueryForName(name, typStr string) []byte {
	typ := dnsmessage.TypeA
	switch strings.ToLower(typStr) {
	case "aaaa":
		typ = dnsmessage.TypeAAAA
	case "txt":
		typ = dnsmessage.TypeTXT
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		OpCode:           0, // query
		RecursionDesired: true,
		ID:               1, // arbitrary, but 0 is rejected by some servers
	})
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	b.StartQuestions()
	b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  typ,
		Class: dnsmessage.ClassINET,
	})
	msg, _ := b.Finish()
	return msg
}

func writePrettyDNSReply(w io.Writer, res []byte) (err error) {
	defer func() {
		if err != nil {
			j, _ := json.Marshal(struct {
				Error string
			}{err.Error()})
			j = append(j, '\n')
			w.Write(j)
			return
		}
	}()
	var p dnsmessage.Parser
	hdr, err := p.Start(res)
	if err != nil {
		return err
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return fmt.Errorf("DNS RCode = %v", hdr.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return err
	}

	var gotIPs []string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return err
		}
		if h.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				return err
			}
			continue
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return err
			}
			gotIPs = append(gotIPs, net.IP(r.A[:]).String())
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return err
			}
			gotIPs = append(gotIPs, net.IP(r.AAAA[:]).String())
		case dnsmessage.TypeTXT:
			r, err := p.TXTResource()
			if err != nil {
				return err
			}
			gotIPs = append(gotIPs, r.TXT...)
		default:
			if err := p.SkipAnswer(); err != nil {
				return err
			}
		}
	}
	j, _ := json.Marshal(gotIPs)
	j = append(j, '\n')
	w.Write(j)
	return nil
}

// httpResponseWrapper wraps an http.ResponseWrite and
// stores the status code and content length.
type httpResponseWrapper struct {
	http.ResponseWriter
	statusCode    int
	contentLength int64
}

// WriteHeader implements the WriteHeader interface.
func (hrw *httpResponseWrapper) WriteHeader(status int) {
	hrw.statusCode = status
	hrw.ResponseWriter.WriteHeader(status)
}

// Write implements the Write interface.
func (hrw *httpResponseWrapper) Write(b []byte) (int, error) {
	n, err := hrw.ResponseWriter.Write(b)
	hrw.contentLength += int64(n)
	return n, err
}

// requestBodyWrapper wraps an io.ReadCloser and stores
// the number of bytesRead.
type requestBodyWrapper struct {
	io.ReadCloser
	bytesRead int64
}

// Read implements the io.Reader interface.
func (rbw *requestBodyWrapper) Read(b []byte) (int, error) {
	n, err := rbw.ReadCloser.Read(b)
	rbw.bytesRead += int64(n)
	return n, err
}

// peerAPIURL returns an HTTP URL for the peer's peerapi service,
// without a trailing slash.
//
// If ip or port is the zero value then it returns the empty string.
func peerAPIURL(ip netip.Addr, port uint16) string {
	if port == 0 || !ip.IsValid() {
		return ""
	}
	return fmt.Sprintf("http://%v", netip.AddrPortFrom(ip, port))
}

// peerAPIBase returns the "http://ip:port" URL base to reach peer's peerAPI.
// It returns the empty string if the peer doesn't support the peerapi
// or there's no matching address family based on the netmap's own addresses.
func peerAPIBase(nm *netmap.NetworkMap, peer tailcfg.NodeView) string {
	if nm == nil || !peer.Valid() || !peer.Hostinfo().Valid() {
		return ""
	}

	var have4, have6 bool
	addrs := nm.GetAddresses()
	for _, a := range addrs.All() {
		if !a.IsSingleIP() {
			continue
		}
		switch {
		case a.Addr().Is4():
			have4 = true
		case a.Addr().Is6():
			have6 = true
		}
	}
	p4, p6 := peerAPIPorts(peer)
	switch {
	case have4 && p4 != 0:
		return peerAPIURL(nodeIP(peer, netip.Addr.Is4), p4)
	case have6 && p6 != 0:
		return peerAPIURL(nodeIP(peer, netip.Addr.Is6), p6)
	}
	return ""
}

// newFakePeerAPIListener creates a new net.Listener that acts like
// it's listening on the provided IP address and on TCP port 1.
//
// See docs on fakePeerAPIListener.
func newFakePeerAPIListener(ip netip.Addr) net.Listener {
	return &fakePeerAPIListener{
		addr:   net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, 1)),
		closed: make(chan struct{}),
	}
}

// fakePeerAPIListener is a net.Listener that has an Addr method returning a TCPAddr
// for a given IP on port 1 (arbitrary) and can be Closed, but otherwise Accept
// just blocks forever until closed. The purpose of this is to let the rest
// of the LocalBackend/PeerAPI code run and think it's talking to the kernel,
// even if the kernel isn't cooperating (like on Android: Issue 4449, 4293, etc)
// or we lack permission to listen on a port. It's okay to not actually listen via
// the kernel because on almost all platforms (except iOS as of 2022-04-20) we
// also intercept incoming netstack TCP requests to our peerapi port and hand them over
// directly to peerapi, without involving the kernel. So this doesn't need to be
// real. But the port number we return (1, in this case) is the port number we advertise
// to peers and they connect to. 1 seems pretty safe to use. Even if the kernel's
// using it, it doesn't matter, as we intercept it first in netstack and the kernel
// never notices.
//
// Eventually we'll remove this code and do this on all platforms, when iOS also uses
// netstack.
type fakePeerAPIListener struct {
	addr net.Addr

	closeOnce sync.Once
	closed    chan struct{}
}

func (fl *fakePeerAPIListener) Close() error {
	fl.closeOnce.Do(func() { close(fl.closed) })
	return nil
}

func (fl *fakePeerAPIListener) Accept() (net.Conn, error) {
	<-fl.closed
	return nil, net.ErrClosed
}

func (fl *fakePeerAPIListener) Addr() net.Addr { return fl.addr }

var (
	metricInvalidRequests = clientmetric.NewCounter("peerapi_invalid_requests")

	// Non-debug PeerAPI endpoints.
	metricDNSCalls = clientmetric.NewCounter("peerapi_dns")
)
