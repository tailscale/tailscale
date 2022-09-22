// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/exp/slices"
	"tailscale.com/health"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/monitor"
)

var (
	magicDNSIP   = tsaddr.TailscaleServiceIP()
	magicDNSIPv6 = tsaddr.TailscaleServiceIPv6()
)

var (
	errFullQueue = errors.New("request queue full")
)

// maxActiveQueries returns the maximal number of DNS requests that be
// can running.
// If EnqueueRequest is called when this many requests are already pending,
// the request will be dropped to avoid blocking the caller.
func maxActiveQueries() int32 {
	if runtime.GOOS == "ios" {
		// For memory paranoia reasons on iOS, match the
		// historical Tailscale 1.x..1.8 behavior for now
		// (just before the 1.10 release).
		return 64
	}
	// But for other platforms, allow more burstiness:
	return 256
}

// We use file-ignore below instead of ignore because on some platforms,
// the lint exception is necessary and on others it is not,
// and plain ignore complains if the exception is unnecessary.

// reconfigTimeout is the time interval within which Manager.{Up,Down} should complete.
//
// This is particularly useful because certain conditions can cause indefinite hangs
// (such as improper dbus auth followed by contextless dbus.Object.Call).
// Such operations should be wrapped in a timeout context.
const reconfigTimeout = time.Second

type response struct {
	pkt []byte
	to  netip.AddrPort // response destination (request source)
}

// Manager manages system DNS settings.
type Manager struct {
	logf logger.Logf

	// When netstack is not used, Manager implements magic DNS.
	// In this case, responses tracks completed DNS requests
	// which need a response, and NextPacket() synthesizes a
	// fake IP+UDP header to finish assembling the response.
	//
	// TODO(tom): Rip out once all platforms use netstack.
	responses           chan response
	activeQueriesAtomic int32

	ctx       context.Context    // good until Down
	ctxCancel context.CancelFunc // closes ctx

	resolver *resolver.Resolver
	os       OSConfigurator
}

// NewManagers created a new manager from the given config.
func NewManager(logf logger.Logf, oscfg OSConfigurator, linkMon *monitor.Mon, dialer *tsdial.Dialer, linkSel resolver.ForwardLinkSelector) *Manager {
	if dialer == nil {
		panic("nil Dialer")
	}
	logf = logger.WithPrefix(logf, "dns: ")
	m := &Manager{
		logf:      logf,
		resolver:  resolver.New(logf, linkMon, linkSel, dialer),
		os:        oscfg,
		responses: make(chan response),
	}
	m.ctx, m.ctxCancel = context.WithCancel(context.Background())
	m.logf("using %T", m.os)
	return m
}

// Resolver returns the Manager's DNS Resolver.
func (m *Manager) Resolver() *resolver.Resolver { return m.resolver }

func (m *Manager) Set(cfg Config) error {
	m.logf("Set: %v", logger.ArgWriter(func(w *bufio.Writer) {
		cfg.WriteToBufioWriter(w)
	}))

	rcfg, ocfg, err := m.compileConfig(cfg)
	if err != nil {
		return err
	}

	m.logf("Resolvercfg: %v", logger.ArgWriter(func(w *bufio.Writer) {
		rcfg.WriteToBufioWriter(w)
	}))
	m.logf("OScfg: %+v", ocfg)

	if err := m.resolver.SetConfig(rcfg); err != nil {
		return err
	}
	if err := m.os.SetDNS(ocfg); err != nil {
		health.SetDNSOSHealth(err)
		return err
	}
	health.SetDNSOSHealth(nil)

	return nil
}

// compileHostEntries creates a list of single-label resolutions possible
// from the configured hosts and search domains.
// The entries are compiled in the order of the search domains, then the hosts.
// The returned list is sorted by the first hostname in each entry.
func compileHostEntries(cfg Config) (hosts []*HostEntry) {
	didLabel := make(map[string]bool, len(cfg.Hosts))
	for _, sd := range cfg.SearchDomains {
		for h, ips := range cfg.Hosts {
			if !sd.Contains(h) || h.NumLabels() != (sd.NumLabels()+1) {
				continue
			}
			ipHosts := []string{string(h.WithTrailingDot())}
			if label := dnsname.FirstLabel(string(h)); !didLabel[label] {
				didLabel[label] = true
				ipHosts = append(ipHosts, label)
			}
			for _, ip := range ips {
				if cfg.OnlyIPv6 && ip.Is4() {
					continue
				}
				hosts = append(hosts, &HostEntry{
					Addr:  ip,
					Hosts: ipHosts,
				})
				// Only add IPv4 or IPv6 per host, like we do in the resolver.
				break
			}
		}
	}
	slices.SortFunc(hosts, func(a, b *HostEntry) bool {
		if len(a.Hosts) == 0 {
			return false
		}
		if len(b.Hosts) == 0 {
			return true
		}
		return a.Hosts[0] < b.Hosts[0]
	})
	return hosts
}

// compileConfig converts cfg into a quad-100 resolver configuration
// and an OS-level configuration.
func (m *Manager) compileConfig(cfg Config) (rcfg resolver.Config, ocfg OSConfig, err error) {
	// The internal resolver always gets MagicDNS hosts and
	// authoritative suffixes, even if we don't propagate MagicDNS to
	// the OS.
	rcfg.Hosts = cfg.Hosts
	routes := map[dnsname.FQDN][]*dnstype.Resolver{} // assigned conditionally to rcfg.Routes below.
	for suffix, resolvers := range cfg.Routes {
		if len(resolvers) == 0 {
			rcfg.LocalDomains = append(rcfg.LocalDomains, suffix)
		} else {
			routes[suffix] = resolvers
		}
	}

	// Similarly, the OS always gets search paths.
	ocfg.SearchDomains = cfg.SearchDomains
	if runtime.GOOS == "windows" {
		ocfg.Hosts = compileHostEntries(cfg)
	}

	// Deal with trivial configs first.
	switch {
	case !cfg.needsOSResolver():
		// Set search domains, but nothing else. This also covers the
		// case where cfg is entirely zero, in which case these
		// configs clear all Tailscale DNS settings.
		return rcfg, ocfg, nil
	case cfg.hasDefaultIPResolversOnly() && !cfg.hasHostsWithoutSplitDNSRoutes():
		// Trivial CorpDNS configuration, just override the OS resolver.
		//
		// If there are hosts (ExtraRecords) that are not covered by an existing
		// SplitDNS route, then we don't go into this path so that we fall into
		// the next case and send the extra record hosts queries through
		// 100.100.100.100 instead where we can answer them.
		//
		// TODO: for OSes that support it, pass IP:port and DoH
		// addresses directly to OS.
		// https://github.com/tailscale/tailscale/issues/1666
		ocfg.Nameservers = toIPsOnly(cfg.DefaultResolvers)
		return rcfg, ocfg, nil
	case cfg.hasDefaultResolvers():
		// Default resolvers plus other stuff always ends up proxying
		// through quad-100.
		rcfg.Routes = routes
		rcfg.Routes["."] = cfg.DefaultResolvers
		ocfg.Nameservers = []netip.Addr{cfg.serviceIP()}
		return rcfg, ocfg, nil
	}

	// From this point on, we're figuring out split DNS
	// configurations. The possible cases don't return directly any
	// more, because as a final step we have to handle the case where
	// the OS can't do split DNS.

	// Workaround for
	// https://github.com/tailscale/corp/issues/1662. Even though
	// Windows natively supports split DNS, it only configures linux
	// containers using whatever the primary is, and doesn't apply
	// NRPT rules to DNS traffic coming from WSL.
	//
	// In order to make WSL work okay when the host Windows is using
	// Tailscale, we need to set up quad-100 as a "full proxy"
	// resolver, regardless of whether Windows itself can do split
	// DNS. We still make Windows do split DNS itself when it can, but
	// quad-100 will still have the full split configuration as well,
	// and so can service WSL requests correctly.
	//
	// This bool is used in a couple of places below to implement this
	// workaround.
	isWindows := runtime.GOOS == "windows"
	if cfg.singleResolverSet() != nil && m.os.SupportsSplitDNS() && !isWindows {
		// Split DNS configuration requested, where all split domains
		// go to the same resolvers. We can let the OS do it.
		ocfg.Nameservers = toIPsOnly(cfg.singleResolverSet())
		ocfg.MatchDomains = cfg.matchDomains()
		return rcfg, ocfg, nil
	}

	// Split DNS configuration with either multiple upstream routes,
	// or routes + MagicDNS, or just MagicDNS, or on an OS that cannot
	// split-DNS. Install a split config pointing at quad-100.
	rcfg.Routes = routes
	ocfg.Nameservers = []netip.Addr{cfg.serviceIP()}

	var baseCfg *OSConfig // base config; non-nil if/when known

	// Even though Apple devices can do split DNS, they don't provide a way to
	// selectively answer ExtraRecords, and ignore other DNS traffic. As a
	// workaround, we read the existing default resolver configuration and use
	// that as the forwarder for all DNS traffic that quad-100 doesn't handle.
	const isApple = runtime.GOOS == "darwin" || runtime.GOOS == "ios"

	if isApple || !m.os.SupportsSplitDNS() {
		// If the OS can't do native split-dns, read out the underlying
		// resolver config and blend it into our config.
		cfg, err := m.os.GetBaseConfig()
		if err == nil {
			baseCfg = &cfg
		} else if isApple && err == ErrGetBaseConfigNotSupported {
			// This is currently (2022-10-13) expected on certain iOS and macOS
			// builds.
		} else {
			health.SetDNSOSHealth(err)
			return resolver.Config{}, OSConfig{}, err
		}
	}

	if baseCfg == nil || isApple && len(baseCfg.Nameservers) == 0 {
		// If there was no base config, or if we're on Apple and the base
		// config is empty, then we need to fallback to SplitDNS mode.
		ocfg.MatchDomains = cfg.matchDomains()
	} else {
		var defaultRoutes []*dnstype.Resolver
		for _, ip := range baseCfg.Nameservers {
			defaultRoutes = append(defaultRoutes, &dnstype.Resolver{Addr: ip.String()})
		}
		rcfg.Routes["."] = defaultRoutes
		ocfg.SearchDomains = append(ocfg.SearchDomains, baseCfg.SearchDomains...)
	}

	return rcfg, ocfg, nil
}

// toIPsOnly returns only the IP portion of dnstype.Resolver.
// Only safe to use if the resolvers slice has been cleared of
// DoH or custom-port entries with something like hasDefaultIPResolversOnly.
func toIPsOnly(resolvers []*dnstype.Resolver) (ret []netip.Addr) {
	for _, r := range resolvers {
		if ipp, ok := r.IPPort(); ok && ipp.Port() == 53 {
			ret = append(ret, ipp.Addr())
		}
	}
	return ret
}

// EnqueuePacket is the legacy path for handling magic DNS traffic, and is
// called with a DNS request payload.
//
// TODO(tom): Rip out once all platforms use netstack.
func (m *Manager) EnqueuePacket(bs []byte, proto ipproto.Proto, from, to netip.AddrPort) error {
	if to.Port() != 53 || proto != ipproto.UDP {
		return nil
	}

	if n := atomic.AddInt32(&m.activeQueriesAtomic, 1); n > maxActiveQueries() {
		atomic.AddInt32(&m.activeQueriesAtomic, -1)
		metricDNSQueryErrorQueue.Add(1)
		return errFullQueue
	}

	go func() {
		resp, err := m.resolver.Query(m.ctx, bs, from)
		if err != nil {
			atomic.AddInt32(&m.activeQueriesAtomic, -1)
			m.logf("dns query: %v", err)
			return
		}

		select {
		case <-m.ctx.Done():
			return
		case m.responses <- response{resp, from}:
		}
	}()
	return nil
}

// NextPacket is the legacy path for obtaining DNS results in response to
// magic DNS queries. It blocks until a response is available.
//
// TODO(tom): Rip out once all platforms use netstack.
func (m *Manager) NextPacket() ([]byte, error) {
	var resp response
	select {
	case <-m.ctx.Done():
		return nil, net.ErrClosed
	case resp = <-m.responses:
		// continue
	}

	// Unused space is needed further down the stack. To avoid extra
	// allocations/copying later on, we allocate such space here.
	const offset = tstun.PacketStartOffset

	var buf []byte
	switch {
	case resp.to.Addr().Is4():
		h := packet.UDP4Header{
			IP4Header: packet.IP4Header{
				Src: magicDNSIP,
				Dst: resp.to.Addr(),
			},
			SrcPort: 53,
			DstPort: resp.to.Port(),
		}
		hlen := h.Len()
		buf = make([]byte, offset+hlen+len(resp.pkt))
		copy(buf[offset+hlen:], resp.pkt)
		h.Marshal(buf[offset:])
	case resp.to.Addr().Is6():
		h := packet.UDP6Header{
			IP6Header: packet.IP6Header{
				Src: magicDNSIPv6,
				Dst: resp.to.Addr(),
			},
			SrcPort: 53,
			DstPort: resp.to.Port(),
		}
		hlen := h.Len()
		buf = make([]byte, offset+hlen+len(resp.pkt))
		copy(buf[offset+hlen:], resp.pkt)
		h.Marshal(buf[offset:])
	}

	atomic.AddInt32(&m.activeQueriesAtomic, -1)
	return buf, nil
}

// Query executes a DNS query received from the given address. The query is
// provided in bs as a wire-encoded DNS query without any transport header.
// This method is called for requests arriving over UDP and TCP.
func (m *Manager) Query(ctx context.Context, bs []byte, from netip.AddrPort) ([]byte, error) {
	select {
	case <-m.ctx.Done():
		return nil, net.ErrClosed
	default:
		// continue
	}

	if n := atomic.AddInt32(&m.activeQueriesAtomic, 1); n > maxActiveQueries() {
		atomic.AddInt32(&m.activeQueriesAtomic, -1)
		metricDNSQueryErrorQueue.Add(1)
		return nil, errFullQueue
	}
	defer atomic.AddInt32(&m.activeQueriesAtomic, -1)
	return m.resolver.Query(ctx, bs, from)
}

const (
	// RFC 7766 6.2 recommends connection reuse & request pipelining
	// be undertaken, and the connection be closed by the server
	// using an idle timeout on the order of seconds.
	idleTimeoutTCP = 45 * time.Second
	// The RFCs don't specify the max size of a TCP-based DNS query,
	// but we want to keep this reasonable. Given payloads are typically
	// much larger and all known client send a single query, I've arbitrarily
	// chosen 2k.
	maxReqSizeTCP = 2048
)

// dnsTCPSession services DNS requests sent over TCP.
type dnsTCPSession struct {
	m *Manager

	conn    net.Conn
	srcAddr netip.AddrPort

	readClosing chan struct{}
	responses   chan []byte // DNS replies pending writing

	ctx      context.Context
	closeCtx context.CancelFunc
}

func (s *dnsTCPSession) handleWrites() {
	defer s.conn.Close()
	defer close(s.responses)
	defer s.closeCtx()

	for {
		select {
		case <-s.readClosing:
			return // connection closed or timeout, teardown time

		case resp := <-s.responses:
			s.conn.SetWriteDeadline(time.Now().Add(idleTimeoutTCP))
			if err := binary.Write(s.conn, binary.BigEndian, uint16(len(resp))); err != nil {
				s.m.logf("tcp write (len): %v", err)
				return
			}
			if _, err := s.conn.Write(resp); err != nil {
				s.m.logf("tcp write (response): %v", err)
				return
			}
		}
	}
}

func (s *dnsTCPSession) handleQuery(q []byte) {
	resp, err := s.m.Query(s.ctx, q, s.srcAddr)
	if err != nil {
		s.m.logf("tcp query: %v", err)
		return
	}

	select {
	case <-s.ctx.Done():
	case s.responses <- resp:
	}
}

func (s *dnsTCPSession) handleReads() {
	defer close(s.readClosing)

	for {
		select {
		case <-s.ctx.Done():
			return

		default:
			s.conn.SetReadDeadline(time.Now().Add(idleTimeoutTCP))
			var reqLen uint16
			if err := binary.Read(s.conn, binary.BigEndian, &reqLen); err != nil {
				if err == io.EOF || err == io.ErrClosedPipe {
					return // connection closed nominally, we gucci
				}
				s.m.logf("tcp read (len): %v", err)
				return
			}
			if int(reqLen) > maxReqSizeTCP {
				s.m.logf("tcp request too large (%d > %d)", reqLen, maxReqSizeTCP)
				return
			}

			buf := make([]byte, int(reqLen))
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				s.m.logf("tcp read (payload): %v", err)
				return
			}

			select {
			case <-s.ctx.Done():
				return
			default:
				go s.handleQuery(buf)
			}
		}
	}
}

// HandleTCPConn implements magicDNS over TCP, taking a connection and
// servicing DNS requests sent down it.
func (m *Manager) HandleTCPConn(conn net.Conn, srcAddr netip.AddrPort) {
	s := dnsTCPSession{
		m:           m,
		conn:        conn,
		srcAddr:     srcAddr,
		responses:   make(chan []byte),
		readClosing: make(chan struct{}),
	}
	s.ctx, s.closeCtx = context.WithCancel(m.ctx)
	go s.handleReads()
	s.handleWrites()
}

func (m *Manager) Down() error {
	m.ctxCancel()
	if err := m.os.Close(); err != nil {
		return err
	}
	m.resolver.Close()
	return nil
}

func (m *Manager) FlushCaches() error {
	return flushCaches()
}

// Cleanup restores the system DNS configuration to its original state
// in case the Tailscale daemon terminated without closing the router.
// No other state needs to be instantiated before this runs.
func Cleanup(logf logger.Logf, interfaceName string) {
	oscfg, err := NewOSConfigurator(logf, interfaceName)
	if err != nil {
		logf("creating dns cleanup: %v", err)
		return
	}
	dns := NewManager(logf, oscfg, nil, &tsdial.Dialer{Logf: logf}, nil)
	if err := dns.Down(); err != nil {
		logf("dns down: %v", err)
	}
}

var (
	metricDNSQueryErrorQueue = clientmetric.NewCounter("dns_query_local_error_queue")
)
