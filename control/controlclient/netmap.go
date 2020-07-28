// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

type NetworkMap struct {
	// Core networking

	NodeKey    tailcfg.NodeKey
	PrivateKey wgcfg.PrivateKey
	Expiry     time.Time
	// Name is the DNS name assigned to this node.
	Name          string
	Addresses     []wgcfg.CIDR
	LocalPort     uint16 // used for debugging
	MachineStatus tailcfg.MachineStatus
	Peers         []*tailcfg.Node // sorted by Node.ID
	DNS           []wgcfg.IP
	DNSDomains    []string
	Hostinfo      tailcfg.Hostinfo
	PacketFilter  filter.Matches

	// DERPMap is the last DERP server map received. It's reused
	// between updates and should not be modified.
	DERPMap *tailcfg.DERPMap

	// Debug knobs from control server for debug or feature gating.
	Debug *tailcfg.Debug

	// ACLs

	User   tailcfg.UserID
	Domain string
	// TODO(crawshaw): reduce UserProfiles to []tailcfg.UserProfile?
	// There are lots of ways to slice this data, leave it up to users.
	UserProfiles map[tailcfg.UserID]tailcfg.UserProfile
	Roles        []tailcfg.Role
	// TODO(crawshaw): Groups       []tailcfg.Group
	// TODO(crawshaw): Capabilities []tailcfg.Capability
}

func (nm NetworkMap) String() string {
	return nm.Concise()
}

func (nm *NetworkMap) Concise() string {
	buf := new(strings.Builder)

	nm.printConciseHeader(buf)
	for _, p := range nm.Peers {
		printPeerConcise(buf, p)
	}
	return buf.String()
}

// printConciseHeader prints a concise header line representing nm to buf.
//
// If this function is changed to access different fields of nm, keep
// in equalConciseHeader in sync.
func (nm *NetworkMap) printConciseHeader(buf *strings.Builder) {
	fmt.Fprintf(buf, "netmap: self: %v auth=%v",
		nm.NodeKey.ShortString(), nm.MachineStatus)
	if nm.LocalPort != 0 {
		fmt.Fprintf(buf, " port=%v", nm.LocalPort)
	}
	if nm.Debug != nil {
		j, _ := json.Marshal(nm.Debug)
		fmt.Fprintf(buf, " debug=%s", j)
	}
	fmt.Fprintf(buf, " %v", nm.Addresses)
	buf.WriteByte('\n')
}

// equalConciseHeader reports whether a and b are equal for the fields
// used by printConciseHeader.
func (a *NetworkMap) equalConciseHeader(b *NetworkMap) bool {
	if a.NodeKey != b.NodeKey ||
		a.MachineStatus != b.MachineStatus ||
		a.LocalPort != b.LocalPort ||
		len(a.Addresses) != len(b.Addresses) {
		return false
	}
	for i, a := range a.Addresses {
		if b.Addresses[i] != a {
			return false
		}
	}
	return (a.Debug == nil && b.Debug == nil) || reflect.DeepEqual(a.Debug, b.Debug)
}

// printPeerConcise appends to buf a line repsenting the peer p.
//
// If this function is changed to access different fields of p, keep
// in nodeConciseEqual in sync.
func printPeerConcise(buf *strings.Builder, p *tailcfg.Node) {
	aip := make([]string, len(p.AllowedIPs))
	for i, a := range p.AllowedIPs {
		s := strings.TrimSuffix(fmt.Sprint(a), "/32")
		aip[i] = s
	}

	ep := make([]string, len(p.Endpoints))
	for i, e := range p.Endpoints {
		// Align vertically on the ':' between IP and port
		colon := strings.IndexByte(e, ':')
		spaces := 0
		for colon > 0 && len(e)+spaces-colon < 6 {
			spaces++
			colon--
		}
		ep[i] = fmt.Sprintf("%21v", e+strings.Repeat(" ", spaces))
	}

	derp := p.DERP
	const derpPrefix = "127.3.3.40:"
	if strings.HasPrefix(derp, derpPrefix) {
		derp = "D" + derp[len(derpPrefix):]
	}

	// Most of the time, aip is just one element, so format the
	// table to look good in that case. This will also make multi-
	// subnet nodes stand out visually.
	fmt.Fprintf(buf, " %v %-2v %-15v : %v\n",
		p.Key.ShortString(), derp,
		strings.Join(aip, " "),
		strings.Join(ep, " "))
}

// nodeConciseEqual reports whether a and b are equal for the fields accessed by printPeerConcise.
func nodeConciseEqual(a, b *tailcfg.Node) bool {
	return a.Key == b.Key &&
		a.DERP == b.DERP &&
		eqCIDRsIgnoreNil(a.AllowedIPs, b.AllowedIPs) &&
		eqStringsIgnoreNil(a.Endpoints, b.Endpoints)
}

func (b *NetworkMap) ConciseDiffFrom(a *NetworkMap) string {
	var diff strings.Builder

	// See if header (non-peers, "bare") part of the network map changed.
	// If so, print its diff lines first.
	if !a.equalConciseHeader(b) {
		diff.WriteByte('-')
		a.printConciseHeader(&diff)
		diff.WriteByte('+')
		b.printConciseHeader(&diff)
	}

	aps, bps := a.Peers, b.Peers
	for len(aps) > 0 && len(bps) > 0 {
		pa, pb := aps[0], bps[0]
		switch {
		case pa.ID == pb.ID:
			if !nodeConciseEqual(pa, pb) {
				diff.WriteByte('-')
				printPeerConcise(&diff, pa)
				diff.WriteByte('+')
				printPeerConcise(&diff, pb)
			}
			aps, bps = aps[1:], bps[1:]
		case pa.ID > pb.ID:
			// New peer in b.
			diff.WriteByte('+')
			printPeerConcise(&diff, pb)
			bps = bps[1:]
		case pb.ID > pa.ID:
			// Deleted peer in b.
			diff.WriteByte('-')
			printPeerConcise(&diff, pa)
			aps = aps[1:]
		}
	}
	for _, pa := range aps {
		diff.WriteByte('-')
		printPeerConcise(&diff, pa)
	}
	for _, pb := range bps {
		diff.WriteByte('+')
		printPeerConcise(&diff, pb)
	}
	return diff.String()
}

func (nm *NetworkMap) JSON() string {
	b, err := json.MarshalIndent(*nm, "", "  ")
	if err != nil {
		return fmt.Sprintf("[json error: %v]", err)
	}
	return string(b)
}

// WGConfigFlags is a bitmask of flags to control the behavior of the
// wireguard configuration generation done by NetMap.WGCfg.
type WGConfigFlags int

const (
	AllowSingleHosts WGConfigFlags = 1 << iota
	AllowSubnetRoutes
	AllowDefaultRoute
	HackDefaultRoute
)

// TODO(bradfitz): UAPI seems to only be used by the old confnode and
// pingnode; delete this when those are deleted/rewritten?
func (nm *NetworkMap) UAPI(flags WGConfigFlags, dnsOverride []wgcfg.IP) string {
	wgcfg, err := nm.WGCfg(log.Printf, flags, dnsOverride)
	if err != nil {
		log.Fatalf("WGCfg() failed unexpectedly: %v", err)
	}
	s, err := wgcfg.ToUAPI()
	if err != nil {
		log.Fatalf("ToUAPI() failed unexpectedly: %v", err)
	}
	return s
}

// EndpointDiscoSuffix is appended to the hex representation of a peer's discovery key
// and is then the sole wireguard endpoint for peers with a non-zero discovery key.
// This form is then recognize by magicsock's CreateEndpoint.
const EndpointDiscoSuffix = ".disco.tailscale:12345"

// WGCfg returns the NetworkMaps's Wireguard configuration.
func (nm *NetworkMap) WGCfg(logf logger.Logf, flags WGConfigFlags, dnsOverride []wgcfg.IP) (*wgcfg.Config, error) {
	cfg := &wgcfg.Config{
		Name:       "tailscale",
		PrivateKey: nm.PrivateKey,
		Addresses:  nm.Addresses,
		ListenPort: nm.LocalPort,
		DNS:        append([]wgcfg.IP(nil), dnsOverride...),
		Peers:      make([]wgcfg.Peer, 0, len(nm.Peers)),
	}

	for _, peer := range nm.Peers {
		if Debug.OnlyDisco && peer.DiscoKey.IsZero() {
			continue
		}
		if (flags&AllowSingleHosts) == 0 && len(peer.AllowedIPs) < 2 {
			logf("wgcfg: %v skipping a single-host peer.", peer.Key.ShortString())
			continue
		}
		cfg.Peers = append(cfg.Peers, wgcfg.Peer{
			PublicKey: wgcfg.Key(peer.Key),
		})
		cpeer := &cfg.Peers[len(cfg.Peers)-1]
		if peer.KeepAlive {
			cpeer.PersistentKeepalive = 25 // seconds
		}

		if !peer.DiscoKey.IsZero() {
			if err := appendEndpoint(cpeer, fmt.Sprintf("%x%s", peer.DiscoKey[:], EndpointDiscoSuffix)); err != nil {
				return nil, err
			}
			cpeer.Endpoints = []wgcfg.Endpoint{{Host: fmt.Sprintf("%x.disco.tailscale", peer.DiscoKey[:]), Port: 12345}}
		} else {
			if err := appendEndpoint(cpeer, peer.DERP); err != nil {
				return nil, err
			}
			for _, ep := range peer.Endpoints {
				if err := appendEndpoint(cpeer, ep); err != nil {
					return nil, err
				}
			}
		}
		for _, allowedIP := range peer.AllowedIPs {
			if allowedIP.Mask == 0 {
				if (flags & AllowDefaultRoute) == 0 {
					logf("wgcfg: %v skipping default route", peer.Key.ShortString())
					continue
				}
				if (flags & HackDefaultRoute) != 0 {
					allowedIP = wgcfg.CIDR{IP: wgcfg.IPv4(10, 0, 0, 0), Mask: 8}
					logf("wgcfg: %v converting default route => %v", peer.Key.ShortString(), allowedIP.String())
				}
			} else if allowedIP.Mask < 32 {
				if (flags & AllowSubnetRoutes) == 0 {
					logf("wgcfg: %v skipping subnet route", peer.Key.ShortString())
					continue
				}
			}
			cpeer.AllowedIPs = append(cpeer.AllowedIPs, allowedIP)
		}
	}

	return cfg, nil
}

func appendEndpoint(peer *wgcfg.Peer, epStr string) error {
	if epStr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(epStr)
	if err != nil {
		return fmt.Errorf("malformed endpoint %q for peer %v", epStr, peer.PublicKey.ShortString())
	}
	port16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port in endpoint %q for peer %v", epStr, peer.PublicKey.ShortString())
	}
	peer.Endpoints = append(peer.Endpoints, wgcfg.Endpoint{Host: host, Port: uint16(port16)})
	return nil
}

// eqStringsIgnoreNil reports whether a and b have the same length and
// contents, but ignore whether a or b are nil.
func eqStringsIgnoreNil(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// eqCIDRsIgnoreNil reports whether a and b have the same length and
// contents, but ignore whether a or b are nil.
func eqCIDRsIgnoreNil(a, b []wgcfg.CIDR) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
