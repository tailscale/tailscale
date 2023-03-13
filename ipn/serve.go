// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
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

// WebHandlerExists checks if the ServeConfig Web handler exists for
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

// IsTCPForwardingAny checks if ServeConfig is currently forwarding
// in TCPForward mode on any port.
// This is exclusive of Web/HTTPS serving.
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

// IsTCPForwardingOnPort checks if ServeConfig is currently forwarding
// in TCPForward mode on the given port.
// This is exclusive of Web/HTTPS serving.
func (sc *ServeConfig) IsTCPForwardingOnPort(port uint16) bool {
	if sc == nil || sc.TCP[port] == nil {
		return false
	}
	return !sc.TCP[port].HTTPS
}

// IsServingWeb checks if ServeConfig is currently serving
// Web/HTTPS on the given port.
// This is exclusive of TCPForwarding.
func (sc *ServeConfig) IsServingWeb(port uint16) bool {
	if sc == nil || sc.TCP[port] == nil {
		return false
	}
	return sc.TCP[port].HTTPS
}

// IsFunnelOn checks if ServeConfig is currently allowing
// funnel traffic for any host:port.
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
//  1. an invite was used to join the Funnel alpha
//  2. HTTPS is enabled on the Tailnet
//  3. the node has the "funnel" nodeAttr
//  4. the port is allowed for Funnel
//
// The nodeAttrs arg should be the node's Self.Capabilities which should contain
// the attribute we're checking for and possibly warning-capabilities for
// Funnel.
func CheckFunnelAccess(port uint16, nodeAttrs []string) error {
	if slices.Contains(nodeAttrs, tailcfg.CapabilityWarnFunnelNoInvite) {
		return errors.New("Funnel not available; an invite is required to join the alpha. See https://tailscale.com/s/no-funnel.")
	}
	if slices.Contains(nodeAttrs, tailcfg.CapabilityWarnFunnelNoHTTPS) {
		return errors.New("Funnel not available; HTTPS must be enabled. See https://tailscale.com/s/https.")
	}
	if !slices.Contains(nodeAttrs, tailcfg.NodeAttrFunnel) {
		return errors.New("Funnel not available; \"funnel\" node attribute not set. See https://tailscale.com/s/no-funnel.")
	}
	return checkFunnelPort(port, nodeAttrs)
}

// checkFunnelPort checks whether the given port is allowed for Funnel.
// It uses the tailcfg.CapabilityFunnelPorts nodeAttr to determine the allowed
// ports.
func checkFunnelPort(wantedPort uint16, nodeAttrs []string) error {
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
