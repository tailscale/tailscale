// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"errors"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

// ServeConfigKey returns a StateKey that stores the
// JSON-encoded ServeConfig for a config profile.
func ServeConfigKey(profileID ProfileID) StateKey {
	return StateKey("_serve/" + profileID)
}

// ServiceConfig contains the config information for a single service.
// it contains a bool to indicate if the service is in Tun mode (L3 forwarding).
// If the service is not in Tun mode, the service is configured by the L4 forwarding
// (TCP ports) and/or the L7 forwarding (http handlers) information.
type ServiceConfig struct {
	// TCP are the list of TCP port numbers that tailscaled should handle for
	// the Tailscale IP addresses. (not subnet routers, etc)
	TCP map[uint16]*TCPPortHandler `json:",omitempty"`

	// Web maps from "$SNI_NAME:$PORT" to a set of HTTP handlers
	// keyed by mount point ("/", "/foo", etc)
	Web map[HostPort]*WebServerConfig `json:",omitempty"`

	// Tun determines if the service should be using L3 forwarding (Tun mode).
	Tun bool `json:",omitempty"`
}

// ServeConfig is the JSON type stored in the StateStore for
// StateKey "_serve/$PROFILE_ID" as returned by ServeConfigKey.
type ServeConfig struct {
	// TCP are the list of TCP port numbers that tailscaled should handle for
	// the Tailscale IP addresses. (not subnet routers, etc)
	TCP map[uint16]*TCPPortHandler `json:",omitempty"`

	// Web maps from "$SNI_NAME:$PORT" to a set of HTTP handlers
	// keyed by mount point ("/", "/foo", etc)
	Web map[HostPort]*WebServerConfig `json:",omitempty"`

	// Services maps from service name (in the form "svc:dns-label") to a ServiceConfig.
	// Which describes the L3, L4, and L7 forwarding information for the service.
	Services map[tailcfg.ServiceName]*ServiceConfig `json:",omitempty"`

	// AllowFunnel is the set of SNI:port values for which funnel
	// traffic is allowed, from trusted ingress peers.
	AllowFunnel map[HostPort]bool `json:",omitempty"`

	// Foreground is a map of an IPN Bus session ID to an alternate foreground serve config that's valid for the
	// life of that WatchIPNBus session ID. This allows the config to specify ephemeral configs that are used
	// in the CLI's foreground mode to ensure ungraceful shutdowns of either the client or the LocalBackend does not
	// expose ports that users are not aware of. In practice this contains any serve config set via 'tailscale
	// serve' command run without the '--bg' flag. ServeConfig contained by Foreground is not expected itself to contain
	// another Foreground block.
	Foreground map[string]*ServeConfig `json:",omitempty"`

	// ETag is the checksum of the serve config that's populated
	// by the LocalClient through the HTTP ETag header during a
	// GetServeConfig request and is translated to an If-Match header
	// during a SetServeConfig request.
	ETag string `json:"-"`
}

// HostPort is an SNI name and port number, joined by a colon.
// There is no implicit port 443. It must contain a colon.
type HostPort string

// Port extracts just the port number from hp.
// An error is reported in the case that the hp does not
// have a valid numeric port ending.
func (hp HostPort) Port() (uint16, error) {
	_, port, err := net.SplitHostPort(string(hp))
	if err != nil {
		return 0, err
	}
	port16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(port16), nil
}

// A FunnelConn wraps a net.Conn that is coming over a
// Funnel connection. It can be used to determine further
// information about the connection, like the source address
// and the target SNI name.
type FunnelConn struct {
	// Conn is the underlying connection.
	net.Conn

	// Target is what was presented in the "Tailscale-Ingress-Target"
	// HTTP header.
	Target HostPort

	// Src is the source address of the connection.
	// This is the address of the client that initiated the
	// connection, not the address of the Tailscale Funnel
	// node which is relaying the connection. That address
	// can be found in Conn.RemoteAddr.
	Src netip.AddrPort
}

// WebServerConfig describes a web server's configuration.
type WebServerConfig struct {
	Handlers map[string]*HTTPHandler // mountPoint => handler
}

// TCPPortHandler describes what to do when handling a TCP
// connection.
type TCPPortHandler struct {
	// HTTPS, if true, means that tailscaled should handle this connection as an
	// HTTPS request as configured by ServeConfig.Web.
	//
	// It is mutually exclusive with TCPForward.
	HTTPS bool `json:",omitempty"`

	// HTTP, if true, means that tailscaled should handle this connection as an
	// HTTP request as configured by ServeConfig.Web.
	//
	// It is mutually exclusive with TCPForward.
	HTTP bool `json:",omitempty"`

	// TCPForward is the IP:port to forward TCP connections to.
	// Whether or not TLS is terminated by tailscaled depends on
	// TerminateTLS.
	//
	// It is mutually exclusive with HTTPS.
	TCPForward string `json:",omitempty"`

	// TerminateTLS, if non-empty, means that tailscaled should terminate the
	// TLS connections before forwarding them to TCPForward, permitting only the
	// SNI name with this value. It is only used if TCPForward is non-empty.
	// (the HTTPS mode uses ServeConfig.Web)
	TerminateTLS string `json:",omitempty"`

	// ProxyProtocol indicates whether to send a PROXY protocol header
	// before forwarding the connection to TCPForward.
	//
	// This is only valid if TCPForward is non-empty.
	ProxyProtocol int `json:",omitzero"`
}

// HTTPHandler is either a path or a proxy to serve.
type HTTPHandler struct {
	// Exactly one of the following may be set.

	Path  string `json:",omitempty"` // absolute path to directory or file to serve
	Proxy string `json:",omitempty"` // http://localhost:3000/, localhost:3030, 3030

	Text string `json:",omitempty"` // plaintext to serve (primarily for testing)

	AcceptAppCaps []tailcfg.PeerCapability `json:",omitempty"` // peer capabilities to forward in grant header, e.g. example.com/cap/mon

	// Redirect, if not empty, is the target URL to redirect requests to.
	// By default, we redirect with HTTP 302 (Found) status.
	// If Redirect starts with '<httpcode>:', then we use that status instead.
	//
	// The target URL supports the following expansion variables:
	//   - ${HOST}: replaced with the request's Host header value
	//   - ${REQUEST_URI}: replaced with the request's full URI (path and query string)
	Redirect string `json:",omitempty"`

	// TODO(bradfitz): bool to not enumerate directories? TTL on mapping for
	// temporary ones? Error codes?
}

// WebHandlerExists reports whether if the ServeConfig Web handler exists for
// the given host:port and mount point.
func (sc *ServeConfig) WebHandlerExists(svcName tailcfg.ServiceName, hp HostPort, mount string) bool {
	h := sc.GetWebHandler(svcName, hp, mount)
	return h != nil
}

// GetWebHandler returns the HTTPHandler for the given host:port and mount point.
// Returns nil if the handler does not exist.
func (sc *ServeConfig) GetWebHandler(svcName tailcfg.ServiceName, hp HostPort, mount string) *HTTPHandler {
	if sc == nil {
		return nil
	}
	if svcName != "" {
		if svc, ok := sc.Services[svcName]; ok && svc.Web != nil {
			if webCfg, ok := svc.Web[hp]; ok {
				return webCfg.Handlers[mount]
			}
		}
		return nil
	}
	if sc.Web[hp] == nil {
		return nil
	}
	return sc.Web[hp].Handlers[mount]
}

// GetTCPPortHandler returns the TCPPortHandler for the given port. If the port
// is not configured, nil is returned. Parameter svcName can be tailcfg.NoService
// for local serve or a service name for a service hosted on node.
func (sc *ServeConfig) GetTCPPortHandler(port uint16, svcName tailcfg.ServiceName) *TCPPortHandler {
	if sc == nil {
		return nil
	}
	if svcName != "" {
		if svc, ok := sc.Services[svcName]; ok && svc != nil {
			return svc.TCP[port]
		}
		return nil
	}
	return sc.TCP[port]
}

// HasPathHandler reports whether if ServeConfig has at least
// one path handler, including foreground configs.
func (sc *ServeConfig) HasPathHandler() bool {
	if sc.Web != nil {
		for _, webServerConfig := range sc.Web {
			for _, httpHandler := range webServerConfig.Handlers {
				if httpHandler.Path != "" {
					return true
				}
			}
		}
	}

	if sc.Foreground != nil {
		for _, fgConfig := range sc.Foreground {
			if fgConfig.HasPathHandler() {
				return true
			}
		}
	}

	return false
}

// IsTCPForwardingAny reports whether ServeConfig is currently forwarding in
// TCPForward mode on any port. This is exclusive of Web/HTTPS serving.
func (sc *ServeConfig) IsTCPForwardingAny() bool {
	if sc == nil || len(sc.TCP) == 0 {
		return false
	}
	for _, h := range sc.TCP {
		if h.TCPForward != "" {
			return true
		}
	}
	return false
}

// IsTCPForwardingOnPort reports whether ServeConfig is currently forwarding
// in TCPForward mode on the given port for local or a service. svcName will
// either be noService (empty string) for local serve or a serviceName for service
// hosted on node. Notice TCPForwarding is exclusive with Web/HTTPS serving.
func (sc *ServeConfig) IsTCPForwardingOnPort(port uint16, svcName tailcfg.ServiceName) bool {
	if sc == nil {
		return false
	}

	if svcName != "" {
		svc, ok := sc.Services[svcName]
		if !ok || svc == nil {
			return false
		}
		if svc.TCP[port] == nil {
			return false
		}
	} else if sc.TCP[port] == nil {
		return false
	}
	return !sc.IsServingWeb(port, svcName)
}

// IsServingWeb reports whether ServeConfig is currently serving Web (HTTP/HTTPS)
// on the given port for local or a service. svcName will be either tailcfg.NoService,
// or a serviceName for service hosted on node. This is exclusive with TCPForwarding.
func (sc *ServeConfig) IsServingWeb(port uint16, svcName tailcfg.ServiceName) bool {
	return sc.IsServingHTTP(port, svcName) || sc.IsServingHTTPS(port, svcName)
}

// IsServingHTTPS reports whether ServeConfig is currently serving HTTPS on
// the given port for local or a service. svcName will be either tailcfg.NoService
// for local serve, or a serviceName for service hosted on node. This is exclusive
// with HTTP and TCPForwarding.
func (sc *ServeConfig) IsServingHTTPS(port uint16, svcName tailcfg.ServiceName) bool {
	if sc == nil {
		return false
	}
	var tcpHandlers map[uint16]*TCPPortHandler
	if svcName != "" {
		if svc := sc.Services[svcName]; svc != nil {
			tcpHandlers = svc.TCP
		}
	} else {
		tcpHandlers = sc.TCP
	}

	th := tcpHandlers[port]
	if th == nil {
		return false
	}
	return th.HTTPS
}

// IsServingHTTP reports whether ServeConfig is currently serving HTTP on the
// given port for local or a service. svcName will be either tailcfg.NoService for
// local serve, or a serviceName for service hosted on node. This is exclusive
// with HTTPS and TCPForwarding.
func (sc *ServeConfig) IsServingHTTP(port uint16, svcName tailcfg.ServiceName) bool {
	if sc == nil {
		return false
	}
	if svcName != "" {
		if svc := sc.Services[svcName]; svc != nil {
			if svc.TCP[port] != nil {
				return svc.TCP[port].HTTP
			}
		}
		return false
	}

	if sc.TCP[port] == nil {
		return false
	}
	return sc.TCP[port].HTTP
}

// FindConfig finds a config that contains the given port, which can be
// the top level background config or an inner foreground one.
// The second result is true if it's foreground.
func (sc *ServeConfig) FindConfig(port uint16) (*ServeConfig, bool) {
	if sc == nil {
		return nil, false
	}
	if _, ok := sc.TCP[port]; ok {
		return sc, false
	}
	for _, sc := range sc.Foreground {
		if _, ok := sc.TCP[port]; ok {
			return sc, true
		}
	}
	return nil, false
}

// SetWebHandler sets the given HTTPHandler at the specified host, port,
// and mount in the serve config. sc.TCP is also updated to reflect web
// serving usage of the given port. The st argument is needed when setting
// a web handler for a service, otherwise it can be nil. mds is the Magic DNS
// suffix, which is used to recreate serve's host.
func (sc *ServeConfig) SetWebHandler(handler *HTTPHandler, host string, port uint16, mount string, useTLS bool, mds string) {
	if sc == nil {
		sc = new(ServeConfig)
	}

	tcpMap := &sc.TCP
	webServerMap := &sc.Web
	hostName := host
	if svcName := tailcfg.AsServiceName(host); svcName != "" {
		hostName = strings.Join([]string{svcName.WithoutPrefix(), mds}, ".")
		svc, ok := sc.Services[svcName]
		if !ok {
			svc = new(ServiceConfig)
			mak.Set(&sc.Services, svcName, svc)
		}
		tcpMap = &svc.TCP
		webServerMap = &svc.Web
	}

	mak.Set(tcpMap, port, &TCPPortHandler{HTTPS: useTLS, HTTP: !useTLS})
	hp := HostPort(net.JoinHostPort(hostName, strconv.Itoa(int(port))))
	webCfg, ok := (*webServerMap)[hp]
	if !ok {
		webCfg = new(WebServerConfig)
		mak.Set(webServerMap, hp, webCfg)
	}
	mak.Set(&webCfg.Handlers, mount, handler)
	// TODO(tylersmalley): handle multiple web handlers from foreground mode
	for k, v := range webCfg.Handlers {
		if v == handler {
			continue
		}
		// If the new mount point ends in / and another mount point
		// shares the same prefix, remove the other handler.
		// (e.g. /foo/ overwrites /foo)
		// The opposite example is also handled.
		m1 := strings.TrimSuffix(mount, "/")
		m2 := strings.TrimSuffix(k, "/")
		if m1 == m2 {
			delete(webCfg.Handlers, k)
		}
	}
}

// SetTCPForwarding sets the fwdAddr (IP:port form) to which to forward
// connections from the given port. If terminateTLS is true, TLS connections
// are terminated with only the given host name permitted before passing them
// to the fwdAddr.
//
// If proxyProtocol is non-zero, the corresponding PROXY protocol version
// header is sent before forwarding the connection.
func (sc *ServeConfig) SetTCPForwarding(port uint16, fwdAddr string, terminateTLS bool, proxyProtocol int, host string) {
	if sc == nil {
		sc = new(ServeConfig)
	}
	tcpPortHandler := &sc.TCP
	if svcName := tailcfg.AsServiceName(host); svcName != "" {
		svcConfig, ok := sc.Services[svcName]
		if !ok {
			svcConfig = new(ServiceConfig)
			mak.Set(&sc.Services, svcName, svcConfig)
		}
		tcpPortHandler = &svcConfig.TCP
	}

	handler := &TCPPortHandler{
		TCPForward:    fwdAddr,
		ProxyProtocol: proxyProtocol, // can be 0
	}
	if terminateTLS {
		handler.TerminateTLS = host
	}
	mak.Set(tcpPortHandler, port, handler)
}

// SetFunnel sets the sc.AllowFunnel value for the given host and port.
func (sc *ServeConfig) SetFunnel(host string, port uint16, setOn bool) {
	if sc == nil {
		sc = new(ServeConfig)
	}
	hp := HostPort(net.JoinHostPort(host, strconv.Itoa(int(port))))

	// TODO(tylersmalley): should ensure there is no other conflicting funnel
	// TODO(tylersmalley): add error handling for if toggling for existing sc
	if setOn {
		mak.Set(&sc.AllowFunnel, hp, true)
	} else if _, exists := sc.AllowFunnel[hp]; exists {
		delete(sc.AllowFunnel, hp)
		// Clear map mostly for testing.
		if len(sc.AllowFunnel) == 0 {
			sc.AllowFunnel = nil
		}
	}
}

// RemoveWebHandler deletes the web handlers at all of the given mount points for the
// provided host and port in the serve config for the node (as opposed to a service).
// If cleanupFunnel is true, this also removes the funnel value for this port if no handlers remain.
func (sc *ServeConfig) RemoveWebHandler(host string, port uint16, mounts []string, cleanupFunnel bool) {
	hp := HostPort(net.JoinHostPort(host, strconv.Itoa(int(port))))

	// Delete existing handler, then cascade delete if empty.
	for _, m := range mounts {
		delete(sc.Web[hp].Handlers, m)
	}
	if len(sc.Web[hp].Handlers) == 0 {
		delete(sc.Web, hp)
		delete(sc.TCP, port)
		if cleanupFunnel {
			delete(sc.AllowFunnel, hp) // disable funnel if no mounts remain for the port
		}
	}

	// Clear empty maps, mostly for testing.
	if len(sc.Web) == 0 {
		sc.Web = nil
	}
	if len(sc.TCP) == 0 {
		sc.TCP = nil
	}
	if len(sc.AllowFunnel) == 0 {
		sc.AllowFunnel = nil
	}
}

// RemoveServiceWebHandler deletes the web handlers at all of the given mount points
// for the provided host and port in the serve config for the given service.
func (sc *ServeConfig) RemoveServiceWebHandler(svcName tailcfg.ServiceName, hostName string, port uint16, mounts []string) {
	hp := HostPort(net.JoinHostPort(hostName, strconv.Itoa(int(port))))

	svc, ok := sc.Services[svcName]
	if !ok || svc == nil {
		return
	}

	// Delete existing handler, then cascade delete if empty.
	for _, m := range mounts {
		delete(svc.Web[hp].Handlers, m)
	}
	if len(svc.Web[hp].Handlers) == 0 {
		delete(svc.Web, hp)
		delete(svc.TCP, port)
	}
	if len(svc.Web) == 0 && len(svc.TCP) == 0 {
		delete(sc.Services, svcName)
	}
	if len(sc.Services) == 0 {
		sc.Services = nil
	}
}

// RemoveTCPForwarding deletes the TCP forwarding configuration for the given
// port from the serve config.
func (sc *ServeConfig) RemoveTCPForwarding(svcName tailcfg.ServiceName, port uint16) {
	if svcName != "" {
		if svc := sc.Services[svcName]; svc != nil {
			delete(svc.TCP, port)
			if len(svc.TCP) == 0 {
				svc.TCP = nil
			}
			if len(svc.Web) == 0 && len(svc.TCP) == 0 {
				delete(sc.Services, svcName)
			}
			if len(sc.Services) == 0 {
				sc.Services = nil
			}
		}
		return
	}
	delete(sc.TCP, port)
	if len(sc.TCP) == 0 {
		sc.TCP = nil
	}
}

// IsFunnelOn reports whether if ServeConfig is currently allowing funnel
// traffic for any host:port.
//
// View version of ServeConfig.IsFunnelOn.
func (v ServeConfigView) IsFunnelOn() bool { return v.ж.IsFunnelOn() }

// IsFunnelOn reports whether any funnel endpoint is currently enabled for this node.
func (sc *ServeConfig) IsFunnelOn() bool {
	if sc == nil {
		return false
	}
	for _, b := range sc.AllowFunnel {
		if b {
			return true
		}
	}
	for _, conf := range sc.Foreground {
		if conf.IsFunnelOn() {
			return true
		}
	}
	return false
}

// CheckFunnelAccess checks whether Funnel access is allowed for the given node
// and port.
// It checks:
//  1. HTTPS is enabled on the tailnet
//  2. the node has the "funnel" nodeAttr
//  3. the port is allowed for Funnel
//
// The node arg should be the ipnstate.Status.Self node.
func CheckFunnelAccess(port uint16, node *ipnstate.PeerStatus) error {
	if err := NodeCanFunnel(node); err != nil {
		return err
	}
	return CheckFunnelPort(port, node)
}

// NodeCanFunnel returns an error if the given node is not configured to allow
// for Tailscale Funnel usage.
func NodeCanFunnel(node *ipnstate.PeerStatus) error {
	if !node.HasCap(tailcfg.CapabilityHTTPS) {
		return errors.New("Funnel not available; HTTPS must be enabled. See https://tailscale.com/s/https.")
	}
	if !node.HasCap(tailcfg.NodeAttrFunnel) {
		return errors.New("Funnel not available; \"funnel\" node attribute not set. See https://tailscale.com/s/no-funnel.")
	}
	return nil
}

// CheckFunnelPort checks whether the given port is allowed for Funnel.
// It uses the tailcfg.CapabilityFunnelPorts nodeAttr to determine the allowed
// ports.
func CheckFunnelPort(wantedPort uint16, node *ipnstate.PeerStatus) error {
	deny := func(allowedPorts string) error {
		if allowedPorts == "" {
			return fmt.Errorf("port %d is not allowed for funnel", wantedPort)
		}
		return fmt.Errorf("port %d is not allowed for funnel; allowed ports are: %v", wantedPort, allowedPorts)
	}
	var portsStr string
	parseAttr := func(attr string) (string, error) {
		u, err := url.Parse(attr)
		if err != nil {
			return "", deny("")
		}
		portsStr := u.Query().Get("ports")
		if portsStr == "" {
			return "", deny("")
		}
		u.RawQuery = ""
		if u.String() != string(tailcfg.CapabilityFunnelPorts) {
			return "", deny("")
		}
		return portsStr, nil
	}
	for attr := range node.CapMap {
		attr := string(attr)
		if !strings.HasPrefix(attr, string(tailcfg.CapabilityFunnelPorts)) {
			continue
		}
		var err error
		portsStr, err = parseAttr(attr)
		if err != nil {
			return err
		}
		break
	}
	if portsStr == "" {
		for attr := range node.CapMap {
			attr := string(attr)
			if !strings.HasPrefix(attr, string(tailcfg.CapabilityFunnelPorts)) {
				continue
			}
			var err error
			portsStr, err = parseAttr(attr)
			if err != nil {
				return err
			}
			break
		}
	}
	if portsStr == "" {
		return deny("")
	}
	wantedPortString := strconv.Itoa(int(wantedPort))
	for _, ps := range strings.Split(portsStr, ",") {
		if ps == "" {
			continue
		}
		first, last, ok := strings.Cut(ps, "-")
		if !ok {
			if first == wantedPortString {
				return nil
			}
			continue
		}
		fp, err := strconv.ParseUint(first, 10, 16)
		if err != nil {
			continue
		}
		lp, err := strconv.ParseUint(last, 10, 16)
		if err != nil {
			continue
		}
		pr := tailcfg.PortRange{First: uint16(fp), Last: uint16(lp)}
		if pr.Contains(wantedPort) {
			return nil
		}
	}
	return deny(portsStr)
}

// ExpandProxyTargetValue expands the supported target values to be proxied
// allowing for input values to be a port number, a partial URL, or a full URL
// including a path. If it's for a service, remote addresses are allowed and
// there doesn't have to be a port specified.
//
// examples:
//   - 3000
//   - localhost:3000
//   - tcp://localhost:3000
//   - http://localhost:3000
//   - https://localhost:3000
//   - https-insecure://localhost:3000
//   - https-insecure://localhost:3000/foo
//   - https://tailscale.com
func ExpandProxyTargetValue(target string, supportedSchemes []string, defaultScheme string) (string, error) {
	const host = "127.0.0.1"

	// empty target is invalid
	if target == "" {
		return "", fmt.Errorf("empty target")
	}

	// support target being a port number
	if port, err := strconv.ParseUint(target, 10, 16); err == nil {
		return fmt.Sprintf("%s://%s:%d", defaultScheme, host, port), nil
	}

	hasScheme := true
	// prepend scheme if not present
	if !strings.Contains(target, "://") {
		target = defaultScheme + "://" + target
		hasScheme = false
	}

	// make sure we can parse the target
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return "", fmt.Errorf("invalid URL %w", err)
	}

	// ensure a supported scheme
	if !slices.Contains(supportedSchemes, u.Scheme) {
		return "", fmt.Errorf("must be a URL starting with one of the supported schemes: %v", supportedSchemes)
	}

	// validate port according to host.
	if u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" {
		// require port for localhost targets
		if u.Port() == "" {
			return "", fmt.Errorf("port required for localhost target %q", target)
		}
	} else {
		validHN := dnsname.ValidHostname(u.Hostname()) == nil
		validIP := net.ParseIP(u.Hostname()) != nil
		if !validHN && !validIP {
			return "", fmt.Errorf("invalid hostname or IP address %q", u.Hostname())
		}
		// require scheme for non-localhost targets
		if !hasScheme {
			return "", fmt.Errorf("non-localhost target %q must include a scheme", target)
		}
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		if u.Port() == "" {
			return u.String(), nil // allow no port for remote destinations
		}
		return "", fmt.Errorf("invalid port %q", u.Port())
	}

	u.Host = fmt.Sprintf("%s:%d", u.Hostname(), port)

	return u.String(), nil
}

// TCPs returns an iterator over both background and foreground TCP
// listeners.
//
// The key is the port number.
func (v ServeConfigView) TCPs() iter.Seq2[uint16, TCPPortHandlerView] {
	return func(yield func(uint16, TCPPortHandlerView) bool) {
		for k, v := range v.TCP().All() {
			if !yield(k, v) {
				return
			}
		}
		for _, conf := range v.Foreground().All() {
			for k, v := range conf.TCP().All() {
				if !yield(k, v) {
					return
				}
			}
		}
	}
}

// Webs returns an iterator over both background and foreground Web configurations.
func (v ServeConfigView) Webs() iter.Seq2[HostPort, WebServerConfigView] {
	return func(yield func(HostPort, WebServerConfigView) bool) {
		for k, v := range v.Web().All() {
			if !yield(k, v) {
				return
			}
		}
		for _, conf := range v.Foreground().All() {
			for k, v := range conf.Web().All() {
				if !yield(k, v) {
					return
				}
			}
		}
		for _, service := range v.Services().All() {
			for k, v := range service.Web().All() {
				if !yield(k, v) {
					return
				}
			}
		}
	}
}

// FindServiceTCP return the TCPPortHandlerView for the given service name and port.
func (v ServeConfigView) FindServiceTCP(svcName tailcfg.ServiceName, port uint16) (res TCPPortHandlerView, ok bool) {
	svcCfg, ok := v.Services().GetOk(svcName)
	if !ok {
		return res, ok
	}
	return svcCfg.TCP().GetOk(port)
}

// FindServiceWeb returns the web handler for the service's host-port.
func (v ServeConfigView) FindServiceWeb(svcName tailcfg.ServiceName, hp HostPort) (res WebServerConfigView, ok bool) {
	if svcCfg, ok := v.Services().GetOk(svcName); ok {
		if res, ok := svcCfg.Web().GetOk(hp); ok {
			return res, ok
		}
	}
	return res, ok
}

// FindTCP returns the first TCP that matches with the given port. It
// prefers a foreground match first followed by a background search if none
// existed.
func (v ServeConfigView) FindTCP(port uint16) (res TCPPortHandlerView, ok bool) {
	res, ok = v.FindForegroundTCP(port)
	if ok {
		return res, ok
	}
	return v.TCP().GetOk(port)
}

// FindWeb returns the first Web that matches with the given HostPort. It
// prefers a foreground match first followed by a background search if none
// existed.
func (v ServeConfigView) FindWeb(hp HostPort) (res WebServerConfigView, ok bool) {
	for _, conf := range v.Foreground().All() {
		if res, ok := conf.Web().GetOk(hp); ok {
			return res, ok
		}
	}
	return v.Web().GetOk(hp)
}

// FindForegroundTCP returns the first foreground TCP handler matching the input
// port.
func (v ServeConfigView) FindForegroundTCP(port uint16) (res TCPPortHandlerView, ok bool) {
	for _, conf := range v.Foreground().All() {
		if res, ok := conf.TCP().GetOk(port); ok {
			return res, ok
		}
	}
	return res, false
}

// HasAllowFunnel returns whether this config has at least one AllowFunnel
// set in the background or foreground configs.
func (v ServeConfigView) HasAllowFunnel() bool {
	if v.AllowFunnel().Len() > 0 {
		return true
	}
	for _, conf := range v.Foreground().All() {
		if conf.AllowFunnel().Len() > 0 {
			return true
		}
	}
	return false
}

// FindFunnel reports whether target exists in either the background AllowFunnel
// or any of the foreground configs.
func (v ServeConfigView) HasFunnelForTarget(target HostPort) bool {
	if v.AllowFunnel().Get(target) {
		return true
	}
	for _, conf := range v.Foreground().All() {
		if conf.AllowFunnel().Get(target) {
			return true
		}
	}
	return false
}

// ServicePortRange returns the list of tailcfg.ProtoPortRange that represents
// the proto/ports pairs that are being served by the service.
//
// Right now Tun mode is the only thing supports UDP, otherwise serve only supports TCP.
func (v ServiceConfigView) ServicePortRange() []tailcfg.ProtoPortRange {
	if v.Tun() {
		// If the service is in Tun mode, means service accept TCP/UDP on all ports.
		return []tailcfg.ProtoPortRange{{Ports: tailcfg.PortRangeAny}}
	}
	tcp := int(ipproto.TCP)

	// Deduplicate the ports.
	servePorts := make(set.Set[uint16])
	for port := range v.TCP().All() {
		if port > 0 {
			servePorts.Add(uint16(port))
		}
	}
	dedupedServePorts := servePorts.Slice()
	slices.Sort(dedupedServePorts)

	var ranges []tailcfg.ProtoPortRange
	for _, p := range dedupedServePorts {
		if n := len(ranges); n > 0 && p == ranges[n-1].Ports.Last+1 {
			ranges[n-1].Ports.Last = p
			continue
		}
		ranges = append(ranges, tailcfg.ProtoPortRange{
			Proto: tcp,
			Ports: tailcfg.PortRange{
				First: p,
				Last:  p,
			},
		})
	}
	return ranges
}
