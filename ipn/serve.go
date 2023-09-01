// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

// ServeConfigKey returns a StateKey that stores the
// JSON-encoded ServeConfig for a config profile.
func ServeConfigKey(profileID ProfileID) StateKey {
	return StateKey("_serve/" + profileID)
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

	// AllowFunnel is the set of SNI:port values for which funnel
	// traffic is allowed, from trusted ingress peers.
	AllowFunnel map[HostPort]bool `json:",omitempty"`
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

// ServeStreamRequest defines the JSON request body
// for the serve stream endpoint
type ServeStreamRequest struct {
	// HostPort is the DNS and port of the tailscale
	// URL.
	HostPort HostPort `json:",omitempty"`

	// Source is the user's serve source
	// as defined in the `tailscale serve`
	// command such as http://127.0.0.1:3000
	Source string `json:",omitempty"`

	// MountPoint is the path prefix for
	// the given HostPort.
	MountPoint string `json:",omitempty"`

	// Funnel indicates whether the request
	// is a serve request or a funnel one.
	Funnel bool `json:",omitempty"`
}

// FunnelRequestLog is the JSON type written out to io.Writers
// watching funnel connections via ipnlocal.StreamServe.
//
// This structure is in development and subject to change.
type FunnelRequestLog struct {
	Time time.Time `json:",omitempty"` // time of request forwarding

	// SrcAddr is the address that initiated the Funnel request.
	SrcAddr netip.AddrPort `json:",omitempty"`

	// The following fields are only populated if the connection
	// initiated from another node on the client's tailnet.

	NodeName        string   `json:",omitempty"` // src node MagicDNS name
	NodeTags        []string `json:",omitempty"` // src node tags
	UserLoginName   string   `json:",omitempty"` // src node's owner login (if not tagged)
	UserDisplayName string   `json:",omitempty"` // src node's owner name (if not tagged)
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
}

// HTTPHandler is either a path or a proxy to serve.
type HTTPHandler struct {
	// Exactly one of the following may be set.

	Path  string `json:",omitempty"` // absolute path to directory or file to serve
	Proxy string `json:",omitempty"` // http://localhost:3000/, localhost:3030, 3030

	Text string `json:",omitempty"` // plaintext to serve (primarily for testing)

	// TODO(bradfitz): bool to not enumerate directories? TTL on mapping for
	// temporary ones? Error codes? Redirects?
}

// WebHandlerExists reports whether if the ServeConfig Web handler exists for
// the given host:port and mount point.
func (sc *ServeConfig) WebHandlerExists(hp HostPort, mount string) bool {
	h := sc.GetWebHandler(hp, mount)
	return h != nil
}

// GetWebHandler returns the HTTPHandler for the given host:port and mount point.
// Returns nil if the handler does not exist.
func (sc *ServeConfig) GetWebHandler(hp HostPort, mount string) *HTTPHandler {
	if sc == nil || sc.Web[hp] == nil {
		return nil
	}
	return sc.Web[hp].Handlers[mount]
}

// GetTCPPortHandler returns the TCPPortHandler for the given port.
// If the port is not configured, nil is returned.
func (sc *ServeConfig) GetTCPPortHandler(port uint16) *TCPPortHandler {
	if sc == nil {
		return nil
	}
	return sc.TCP[port]
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

// IsTCPForwardingOnPort reports whether if ServeConfig is currently forwarding
// in TCPForward mode on the given port. This is exclusive of Web/HTTPS serving.
func (sc *ServeConfig) IsTCPForwardingOnPort(port uint16) bool {
	if sc == nil || sc.TCP[port] == nil {
		return false
	}
	return !sc.IsServingWeb(port)
}

// IsServingWeb reports whether if ServeConfig is currently serving Web
// (HTTP/HTTPS) on the given port. This is exclusive of TCPForwarding.
func (sc *ServeConfig) IsServingWeb(port uint16) bool {
	return sc.IsServingHTTP(port) || sc.IsServingHTTPS(port)
}

// IsServingHTTPS reports whether if ServeConfig is currently serving HTTPS on
// the given port. This is exclusive of HTTP and TCPForwarding.
func (sc *ServeConfig) IsServingHTTPS(port uint16) bool {
	if sc == nil || sc.TCP[port] == nil {
		return false
	}
	return sc.TCP[port].HTTPS
}

// IsServingHTTP reports whether if ServeConfig is currently serving HTTP on the
// given port. This is exclusive of HTTPS and TCPForwarding.
func (sc *ServeConfig) IsServingHTTP(port uint16) bool {
	if sc == nil || sc.TCP[port] == nil {
		return false
	}
	return sc.TCP[port].HTTP
}

// IsFunnelOn reports whether if ServeConfig is currently allowing funnel
// traffic for any host:port.
//
// View version of ServeConfig.IsFunnelOn.
func (v ServeConfigView) IsFunnelOn() bool { return v.ж.IsFunnelOn() }

// IsFunnelOn reports whether if ServeConfig is currently allowing funnel
// traffic for any host:port.
func (sc *ServeConfig) IsFunnelOn() bool {
	if sc == nil {
		return false
	}
	for _, b := range sc.AllowFunnel {
		if b {
			return true
		}
	}
	return false
}

// CheckFunnelAccess checks whether Funnel access is allowed for the given node
// and port.
// It checks:
//  1. HTTPS is enabled on the Tailnet
//  2. the node has the "funnel" nodeAttr
//  3. the port is allowed for Funnel
//
// The nodeAttrs arg should be the node's Self.Capabilities which should contain
// the attribute we're checking for and possibly warning-capabilities for
// Funnel.
func CheckFunnelAccess(port uint16, nodeAttrs []string) error {
	if !slices.Contains(nodeAttrs, tailcfg.CapabilityHTTPS) {
		return errors.New("Funnel not available; HTTPS must be enabled. See https://tailscale.com/s/https.")
	}
	if !slices.Contains(nodeAttrs, tailcfg.NodeAttrFunnel) {
		return errors.New("Funnel not available; \"funnel\" node attribute not set. See https://tailscale.com/s/no-funnel.")
	}
	return CheckFunnelPort(port, nodeAttrs)
}

// CheckFunnelPort checks whether the given port is allowed for Funnel.
// It uses the tailcfg.CapabilityFunnelPorts nodeAttr to determine the allowed
// ports.
func CheckFunnelPort(wantedPort uint16, nodeAttrs []string) error {
	deny := func(allowedPorts string) error {
		if allowedPorts == "" {
			return fmt.Errorf("port %d is not allowed for funnel", wantedPort)
		}
		return fmt.Errorf("port %d is not allowed for funnel; allowed ports are: %v", wantedPort, allowedPorts)
	}
	var portsStr string
	for _, attr := range nodeAttrs {
		if !strings.HasPrefix(attr, tailcfg.CapabilityFunnelPorts) {
			continue
		}
		u, err := url.Parse(attr)
		if err != nil {
			return deny("")
		}
		portsStr = u.Query().Get("ports")
		if portsStr == "" {
			return deny("")
		}
		u.RawQuery = ""
		if u.String() != tailcfg.CapabilityFunnelPorts {
			return deny("")
		}
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
