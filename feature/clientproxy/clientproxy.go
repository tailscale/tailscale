// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package clientproxy runs a loopback (127.0.0.1) HTTP server that lets a
// browser-based Tailscale client (e.g. the web client portal served from
// my.tailscale.com) use this locally-running tailscaled as its backend.
//
// The browser talks to this server over plain HTTP on loopback. That is safe
// and allowed from an HTTPS page: loopback addresses are "potentially
// trustworthy" origins (W3C Secure Contexts), so the request is not blocked as
// mixed content, and traffic never leaves the machine. The one extra gate is
// Chrome's Private Network Access preflight, which we satisfy with the
// Access-Control-Allow-Private-Network response header.
//
// Because the transport is unauthenticated plain HTTP, the Origin allowlist is
// the entire security model: every endpoint (including the /dial WebSocket, for
// which browsers send no CORS preflight) rejects requests whose Origin is not a
// known Tailscale web-client host. The /dial target is additionally restricted
// to tailnet service VIP addresses visible in this node's netmap, so an
// allowlisted page cannot use us to reach arbitrary tailnet host:ports.
//
// It exposes:
//
//	GET  /            -> 204 (liveness probe for detection)
//	GET  /health      -> 204
//	GET  /services    -> JSON []Service   (projection of netMap.Services())
//	GET  /profile     -> JSON Profile     (logged-in user/device/tailnet)
//	GET  /dial?target=<ip:port> (WebSocket) -> raw TCP proxy to the tailnet target
//
// The /services and /profile projections mirror the WASM netmap-only client in
// the client-portal repo (wasm/internal/network/tailscale/shared_device.go), so
// the browser consumes an identical shape whether it talks to the in-browser
// WASM device or this native proxy.
package clientproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/coder/websocket"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/wsconn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
)

// allowedOrigins is the set of web origins permitted to call this proxy. Because
// the transport is plain HTTP on loopback, this allowlist is the security
// boundary. Dev origins are included so the client-portal Vite dev server works.
var allowedOrigins = map[string]bool{
	"https://my.tailscale.com":         true,
	"https://my.staging.tailscale.com": true,
	"http://localhost:8000":            true, // client-portal `make dev` (docker compose)
	"http://127.0.0.1:8000":            true,
	"http://localhost:5173":            true, // client-portal `npm run dev` (vite)
	"http://localhost:3000":            true,
}

// dialTimeout bounds how long a single /dial UserDial may take to establish.
const dialTimeout = 30 * time.Second

// Start runs the loopback client proxy on 127.0.0.1:port until ctx is canceled.
// It returns an error only if the listener cannot be created; serving errors are
// logged. The server is shut down when ctx is done.
func Start(ctx context.Context, logf logger.Logf, lb *ipnlocal.LocalBackend, port int) error {
	s := &server{logf: logf, lb: lb}

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("clientproxy: listen on %s: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/services", s.handleServices)
	mux.HandleFunc("/profile", s.handleProfile)
	mux.HandleFunc("/dial", s.handleDial)

	httpSrv := &http.Server{Handler: mux}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	go func() {
		logf("clientproxy: serving on http://%s", addr)
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("clientproxy: serve error: %v", err)
		}
	}()

	return nil
}

type server struct {
	logf logger.Logf
	lb   *ipnlocal.LocalBackend
}

// setCORS writes the CORS + Private Network Access headers for an allowed
// origin. It reports whether the request's Origin is allowed; callers must not
// serve a response body when it returns false.
func (s *server) setCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if !allowedOrigins[origin] {
		return false
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Vary", "Origin")
	h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	// Satisfy Chrome's Private/Local Network Access preflight for requests from
	// an HTTPS (public) page to this loopback (private) server.
	h.Set("Access-Control-Allow-Private-Network", "true")
	return true
}

// cors handles the CORS/PNA preflight and origin check for a plain HTTP
// endpoint. It returns true if the caller should proceed to serve the request.
func (s *server) cors(w http.ResponseWriter, r *http.Request) bool {
	allowed := s.setCORS(w, r)
	if r.Method == http.MethodOptions {
		// Preflight: answer even for disallowed origins (without ACAO) so the
		// browser gets a clean negative rather than a hanging request.
		if allowed {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "origin not allowed", http.StatusForbidden)
		}
		return false
	}
	if !allowed {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return false
	}
	return true
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !s.cors(w, r) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.cors(w, r) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleServices(w http.ResponseWriter, r *http.Request) {
	if !s.cors(w, r) {
		return
	}
	nm := s.lb.NetMap()
	if nm == nil {
		http.Error(w, "netmap not available yet", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, listServices(nm))
}

func (s *server) handleProfile(w http.ResponseWriter, r *http.Request) {
	if !s.cors(w, r) {
		return
	}
	nm := s.lb.NetMap()
	if nm == nil {
		http.Error(w, "netmap not available yet", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, getProfile(nm))
}

// handleDial proxies raw TCP bytes between a WebSocket (binary frames) and a
// tailnet connection dialed to the ?target=<ip:port>. The origin allowlist is
// enforced here before the upgrade, because browsers apply neither CORS nor PNA
// preflights to WebSocket handshakes.
func (s *server) handleDial(w http.ResponseWriter, r *http.Request) {
	if !allowedOrigins[r.Header.Get("Origin")] {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	target := r.URL.Query().Get("target")
	addrPort, err := netip.ParseAddrPort(target)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid target %q: %v", target, err), http.StatusBadRequest)
		return
	}

	nm := s.lb.NetMap()
	if nm == nil {
		http.Error(w, "netmap not available yet", http.StatusServiceUnavailable)
		return
	}
	// Restrict dialing to tailnet service VIPs this node can see, so an
	// allowlisted page cannot use us to reach arbitrary tailnet host:ports.
	if !socketReachableInTailnet(nm, addrPort.Addr()) {
		http.Error(w, fmt.Sprintf("target %s is not a reachable tailnet service", addrPort.Addr()), http.StatusForbidden)
		return
	}

	// We enforced the origin check above; disable the library's own same-origin
	// check (our page is deliberately cross-origin).
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns:  []string{"*"},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		s.logf("clientproxy: websocket accept: %v", err)
		return
	}
	defer c.Close(websocket.StatusInternalError, "closing")

	dialCtx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	conn, err := s.lb.Dialer().UserDial(dialCtx, "tcp", addrPort.String())
	cancel()
	if err != nil {
		s.logf("clientproxy: dial %s: %v", addrPort, err)
		c.Close(websocket.StatusInternalError, "dial failed")
		return
	}
	defer conn.Close()

	// The WebSocket lifetime is the connection lifetime (r.Context() is canceled
	// when the request ends), so use it for the net.Conn adapter.
	wsNetConn := wsconn.NetConn(r.Context(), c, websocket.MessageBinary, r.RemoteAddr)

	errc := make(chan error, 2)
	go func() { _, err := io.Copy(conn, wsNetConn); errc <- err }()
	go func() { _, err := io.Copy(wsNetConn, conn); errc <- err }()
	<-errc

	c.Close(websocket.StatusNormalClosure, "")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ServiceAction is a plain, JSON-marshallable projection of tailcfg.ServiceAction.
// It mirrors the client-portal WASM type in shared_device.go.
type ServiceAction struct {
	Type         string `json:"type"`
	Port         int    `json:"port"`
	DisplayName  string `json:"displayName"`
	SkipUsername bool   `json:"skipUsername"`
	WebClientURL string `json:"webClientURL"`
	ResourceName string `json:"resourceName"`
}

// Service is a plain, JSON-marshallable projection of tailcfg.ServiceDetails.
// It mirrors the client-portal WASM type in shared_device.go.
type Service struct {
	Name        string          `json:"name"`
	FQDN        string          `json:"fqdn"`
	DisplayName string          `json:"displayName"`
	Addrs       []string        `json:"addrs"`
	Actions     []ServiceAction `json:"actions"`
	Ports       []int           `json:"ports"`
}

// Profile is the logged-in user + device + tailnet identity read from the
// netmap. It mirrors the client-portal WASM type in shared_device.go.
type Profile struct {
	DisplayName    string   `json:"displayName"`
	LoginName      string   `json:"loginName"`
	ProfilePicURL  string   `json:"profilePicURL"`
	Tailnet        string   `json:"tailnet"`
	MagicDNSSuffix string   `json:"magicDNSSuffix"`
	DeviceName     string   `json:"deviceName"`
	TailscaleIPs   []string `json:"tailscaleIPs"`
}

// socketReachableInTailnet reports whether ip is assigned to any Tailscale
// service (VIP service) visible to this node in the netmap. Mirrors the
// client-portal check in tailscale.go so both sides agree on reachability.
func socketReachableInTailnet(nm *netmap.NetworkMap, ip netip.Addr) bool {
	if nm == nil {
		return false
	}
	for _, svc := range nm.Services() {
		for _, addr := range svc.Addrs {
			if addr == ip {
				return true
			}
		}
	}
	return false
}

// listServices projects the netmap's VIP services into the browser-facing
// shape. It mirrors ListServices in the client-portal WASM code.
func listServices(nm *netmap.NetworkMap) []Service {
	magicDNSSuffix := nm.MagicDNSSuffix()

	svcs := nm.Services()
	out := make([]Service, 0, len(svcs))
	for _, details := range svcs {
		// Order IPv4 addresses before IPv6 so callers can prefer Addrs[0].
		addrs := make([]string, 0, len(details.Addrs))
		var v6 []string
		for _, a := range details.Addrs {
			if a.Is4() {
				addrs = append(addrs, a.String())
			} else {
				v6 = append(v6, a.String())
			}
		}
		addrs = append(addrs, v6...)

		actions := make([]ServiceAction, 0, len(details.Actions))
		for _, a := range details.Actions {
			skipUsername := false
			if raw, ok := a.Attributes[tailcfg.ServiceActionAttributeSkipUsername]; ok {
				var v bool
				if err := json.Unmarshal([]byte(raw), &v); err == nil {
					skipUsername = v
				}
			}
			actions = append(actions, ServiceAction{
				Type:         string(a.Type),
				Port:         int(a.Port),
				DisplayName:  a.DisplayName,
				SkipUsername: skipUsername,
				WebClientURL: jsonStringAttr(a.Attributes, tailcfg.ServiceActionAttributeWebClientURL),
				ResourceName: jsonStringAttr(a.Attributes, tailcfg.ServiceActionAttributeResourceName),
			})
		}

		// Concrete single TCP ports, used as the fallback when no typed Actions
		// are advertised. Skip wildcard/large ranges.
		var ports []int
		for _, p := range details.Ports {
			if p.Proto != 0 && p.Proto != int(ipproto.TCP) {
				continue
			}
			if p.Ports.First != 0 && p.Ports.First == p.Ports.Last {
				ports = append(ports, int(p.Ports.First))
			}
		}

		// Build the service FQDN: "<name-without-svc-prefix>.<magicDNS suffix>".
		var fqdn string
		if bare := details.Name.WithoutPrefix(); bare != "" && magicDNSSuffix != "" {
			fqdn = bare + "." + magicDNSSuffix
		}

		out = append(out, Service{
			Name:        string(details.Name),
			FQDN:        fqdn,
			DisplayName: details.DisplayName,
			Addrs:       addrs,
			Actions:     actions,
			Ports:       ports,
		})
	}
	return out
}

// getProfile reads the logged-in user/device/tailnet identity from the netmap.
// It mirrors GetProfile in the client-portal WASM code.
func getProfile(nm *netmap.NetworkMap) Profile {
	tailnet := nm.TailnetDisplayName()
	if tailnet == "" {
		tailnet = nm.Domain
	}
	p := Profile{
		Tailnet:        tailnet,
		MagicDNSSuffix: nm.MagicDNSSuffix(),
	}

	if up, ok := nm.UserProfiles[nm.User()]; ok && up.Valid() {
		p.DisplayName = up.DisplayName()
		p.LoginName = up.LoginName()
		p.ProfilePicURL = up.ProfilePicURL()
	}

	if nm.SelfNode.Valid() {
		p.DeviceName = nm.SelfNode.Name()
		if p.DeviceName == "" {
			p.DeviceName = nm.SelfNode.Hostinfo().Hostname()
		}
		for _, a := range nm.SelfNode.Addresses().All() {
			p.TailscaleIPs = append(p.TailscaleIPs, a.Addr().String())
		}
	}

	return p
}

// jsonStringAttr decodes a JSON-string service-action attribute, returning ""
// if the attribute is absent or not a valid JSON string.
func jsonStringAttr(attrs map[tailcfg.ServiceActionAttribute]tailcfg.RawMessage, key tailcfg.ServiceActionAttribute) string {
	raw, ok := attrs[key]
	if !ok {
		return ""
	}
	var v string
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return ""
	}
	return v
}
