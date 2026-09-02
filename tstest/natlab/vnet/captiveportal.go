// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PortalStyle is how a network's captive portal announces itself, mirroring the
// behaviors seen in the wild.
type PortalStyle string

const (
	// PortalRedirect answers HTTP on port 80, for any destination and any Host
	// header, with a redirect to the portal's login page. This is what most
	// enterprise and hospitality gateways do (Meraki, Aruba, UniFi).
	PortalRedirect PortalStyle = "redirect"

	// PortalMetaRefresh answers with 200 and an HTML page carrying a
	// meta-refresh to the login page, rather than a redirect. Cisco ISE and
	// FortiGate behave this way, on the theory that not every client follows
	// redirects.
	PortalMetaRefresh PortalStyle = "meta-refresh"

	// PortalBlockPage answers with a terminal HTML error page: no redirect, no
	// onward URL, no login form. This is not a captive portal at all — it's
	// what a transparent enterprise web proxy does to a blocked destination —
	// and it exists here so tests can prove detection stays quiet.
	PortalBlockPage PortalStyle = "block-page"

	// PortalSilent never answers HTTP at all: traffic to every destination,
	// the gateway included, is dropped. This is the harshest walled garden,
	// and the one where HTTP probing can learn nothing whatsoever, so a
	// hijacked resolver is the only thing left to find. Combine with
	// HijackDNS.
	PortalSilent PortalStyle = "silent"
)

// CaptivePortal makes a network behave like one behind a captive portal.
//
// A portalled network drops traffic to everything on the virtual Internet —
// including vnet's own fake DERP and control servers — because that is the
// defining property of a walled garden and the condition detection has to cope
// with. Only the portal's own HTTP responses, DHCP, ARP and DNS still work.
type CaptivePortal struct {
	// Style is how the portal responds to HTTP on port 80.
	Style PortalStyle

	// LoginURL is the page the portal sends clients to. Required for
	// [PortalRedirect] and [PortalMetaRefresh], ignored otherwise.
	LoginURL string

	// InterceptHTTP makes the portal answer port 80 for every destination,
	// as an inline transparent proxy does.
	//
	// When false, the portal answers only on the gateway's own address and
	// traffic to anywhere else is dropped. That is the DNS-driven walled
	// garden, and it is the more common design: a probe sent to a literal IP
	// goes nowhere at all, and only a request for a name — which the hijacked
	// resolver points at the portal — gets a reply. Pair it with HijackDNS.
	InterceptHTTP bool

	// HijackDNS makes the network's DNS server answer every A and AAAA query
	// with the portal's own address instead of the real one, which is how a
	// portal gets a browser to knock on its door.
	HijackDNS bool
}

func (p *CaptivePortal) check() error {
	if p == nil {
		return nil
	}
	switch p.Style {
	case PortalRedirect, PortalMetaRefresh:
		if p.LoginURL == "" {
			return fmt.Errorf("captive portal style %q requires a LoginURL", p.Style)
		}
	case PortalBlockPage, PortalSilent:
	default:
		return fmt.Errorf("unknown captive portal style %q", p.Style)
	}
	return nil
}

// SetCaptivePortal puts the network behind a captive portal, or removes it when
// p is nil. It must be called before [New].
func (n *Network) SetCaptivePortal(p *CaptivePortal) {
	if err := p.check(); err != nil {
		n.err = err
		return
	}
	n.portal = p
}

// LANIP4 returns the network's LAN IPv4 prefix, with the router's own address
// in the host bits (e.g. 192.168.0.1/24).
func (n *Network) LANIP4() netip.Prefix { return n.lanIP4 }

// GatewayIP4 returns the router's LAN IPv4 address, which is also the address a
// captive portal on this network answers on.
func (n *Network) GatewayIP4() netip.Addr { return n.lanIP4.Addr() }

// portalAddr returns the address the portal answers on, which is the router's
// own LAN address: a portal has to be reachable from a client that hasn't
// authenticated yet, so it lives on the gateway.
func (n *network) portalAddr() netip.Addr { return n.lanIP4.Addr() }

// shouldInterceptTCP reports whether a TCP packet should be terminated locally
// by this network's netstack rather than routed on.
//
// On a portalled network this is where the portal takes over port 80 from
// whatever server the client actually asked for. Anything it declines falls
// through to the router's default behavior of dropping traffic it doesn't
// handle, which is what makes a portalled network a walled garden.
func (n *network) shouldInterceptTCP(pkt gopacket.Packet) bool {
	if p := n.portal; p != nil {
		if p.Style == PortalSilent {
			// Nothing answers; the router drops it all.
			return false
		}
		tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || tcp.DstPort != 80 {
			return false
		}
		if p.InterceptHTTP {
			return true
		}
		// Not intercepting: the portal answers only for itself. See
		// [CaptivePortal.InterceptHTTP].
		f, ok := flow(pkt)
		return ok && f.dst == n.portalAddr()
	}
	return n.s.shouldInterceptTCP(pkt)
}

// portalDNSHijackAddr returns the address every DNS answer should be rewritten
// to for a query from srcMAC, or an invalid addr if that node's network isn't
// hijacking DNS.
func (s *Server) portalDNSHijackAddr(srcMAC net.HardwareAddr) netip.Addr {
	mac, ok := macOf(srcMAC)
	if !ok {
		return netip.Addr{}
	}
	node, ok := s.nodeByMAC[mac]
	if !ok || node.net == nil {
		return netip.Addr{}
	}
	if p := node.net.portal; p == nil || !p.HijackDNS {
		return netip.Addr{}
	}
	return node.net.portalAddr()
}

// portalHandler returns the HTTP handler that impersonates every server the
// client tries to reach over port 80.
func (n *network) portalHandler() http.Handler {
	p := n.portal
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p.Style {
		case PortalRedirect:
			http.Redirect(w, r, p.LoginURL, http.StatusFound)
		case PortalMetaRefresh:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<!DOCTYPE html><html><head>`+
				`<meta http-equiv="refresh" content="0; url=%s">`+
				`</head><body>Redirecting to the login page.</body></html>`, p.LoginURL)
		case PortalBlockPage:
			// Deliberately terminal: no redirect, no onward URL, no form. See
			// [PortalBlockPage].
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Access Denied</title></head>`+
				`<body><h1>Access Denied</h1><p>This site is blocked by your `+
				`organization's security policy.</p></body></html>`)
		default:
			http.Error(w, "unreachable portal style", http.StatusInternalServerError)
		}
	})
}
