// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

type NetworkMap struct {
	// Core networking

	NodeKey       tailcfg.NodeKey
	PrivateKey    wgcfg.PrivateKey
	Expiry        time.Time
	Addresses     []wgcfg.CIDR
	LocalPort     uint16 // used for debugging
	MachineStatus tailcfg.MachineStatus
	Peers         []*tailcfg.Node
	DNS           []wgcfg.IP
	DNSDomains    []string
	Hostinfo      tailcfg.Hostinfo
	PacketFilter  filter.Matches

	// DERPMap is the last DERP server map received. It's reused
	// between updates and should not be modified.
	DERPMap *tailcfg.DERPMap

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

func (n *NetworkMap) Equal(n2 *NetworkMap) bool {
	// TODO(crawshaw): this is crude, but is an easy way to avoid bugs.
	b, err := json.Marshal(n)
	if err != nil {
		panic(err)
	}
	b2, err := json.Marshal(n2)
	if err != nil {
		panic(err)
	}
	return bytes.Equal(b, b2)
}

func (nm NetworkMap) String() string {
	return nm.Concise()
}

func (nm *NetworkMap) Concise() string {
	buf := new(strings.Builder)
	fmt.Fprintf(buf, "netmap: self: %v auth=%v :%v %v\n",
		nm.NodeKey.ShortString(), nm.MachineStatus,
		nm.LocalPort, nm.Addresses)
	for _, p := range nm.Peers {
		aip := make([]string, len(p.AllowedIPs))
		for i, a := range p.AllowedIPs {
			s := fmt.Sprint(a)
			if strings.HasSuffix(s, "/32") {
				s = s[0 : len(s)-3]
			}
			aip[i] = s
		}

		ep := make([]string, len(p.Endpoints))
		for i, e := range p.Endpoints {
			// Align vertically on the ':' between IP and port
			colon := strings.IndexByte(e, ':')
			for colon > 0 && len(e)-colon < 6 {
				e += " "
				colon--
			}
			ep[i] = fmt.Sprintf("%21v", e)
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
	return buf.String()
}

func (b *NetworkMap) ConciseDiffFrom(a *NetworkMap) string {
	out := []string{}
	ra := strings.Split(a.Concise(), "\n")
	rb := strings.Split(b.Concise(), "\n")

	ma := map[string]struct{}{}
	for _, s := range ra {
		ma[s] = struct{}{}
	}

	mb := map[string]struct{}{}
	for _, s := range rb {
		mb[s] = struct{}{}
	}

	for _, s := range ra {
		if _, ok := mb[s]; !ok {
			out = append(out, "-"+s)
		}
	}
	for _, s := range rb {
		if _, ok := ma[s]; !ok {
			out = append(out, "+"+s)
		}
	}
	return strings.Join(out, "\n")
}

func (nm *NetworkMap) JSON() string {
	b, err := json.MarshalIndent(*nm, "", "  ")
	if err != nil {
		return fmt.Sprintf("[json error: %v]", err)
	}
	return string(b)
}

const (
	UAllowSingleHosts = 1 << iota
	UAllowSubnetRoutes
	UAllowDefaultRoute
	UHackDefaultRoute

	UDefault = 0
)

// Several programs need to parse these arguments into uflags, so let's
// centralize it here.
func UFlagsHelper(uroutes, rroutes, droutes bool) int {
	uflags := 0
	if uroutes {
		uflags |= UAllowSingleHosts
	}
	if rroutes {
		uflags |= UAllowSubnetRoutes
	}
	if droutes {
		uflags |= UAllowDefaultRoute
	}
	return uflags
}

// TODO(bradfitz): UAPI seems to only be used by the old confnode and
// pingnode; delete this when those are deleted/rewritten?
func (nm *NetworkMap) UAPI(uflags int, dnsOverride []wgcfg.IP) string {
	wgcfg, err := nm.WGCfg(uflags, dnsOverride)
	if err != nil {
		log.Fatalf("WGCfg() failed unexpectedly: %v\n", err)
	}
	s, err := wgcfg.ToUAPI()
	if err != nil {
		log.Fatalf("ToUAPI() failed unexpectedly: %v\n", err)
	}
	return s
}

func (nm *NetworkMap) WGCfg(uflags int, dnsOverride []wgcfg.IP) (*wgcfg.Config, error) {
	s := nm._WireGuardConfig(uflags, dnsOverride, true)
	return wgcfg.FromWgQuick(s, "tailscale")
}

func (nm *NetworkMap) _WireGuardConfig(uflags int, dnsOverride []wgcfg.IP, allEndpoints bool) string {
	buf := new(strings.Builder)
	fmt.Fprintf(buf, "[Interface]\n")
	fmt.Fprintf(buf, "PrivateKey = %s\n", base64.StdEncoding.EncodeToString(nm.PrivateKey[:]))
	if len(nm.Addresses) > 0 {
		fmt.Fprintf(buf, "Address = ")
		for i, cidr := range nm.Addresses {
			if i > 0 {
				fmt.Fprintf(buf, ", ")
			}
			fmt.Fprintf(buf, "%s", cidr)
		}
		fmt.Fprintf(buf, "\n")
	}
	fmt.Fprintf(buf, "ListenPort = %d\n", nm.LocalPort)
	if len(dnsOverride) > 0 {
		dnss := []string{}
		for _, ip := range dnsOverride {
			dnss = append(dnss, ip.String())
		}
		fmt.Fprintf(buf, "DNS = %s\n", strings.Join(dnss, ","))
	}
	fmt.Fprintf(buf, "\n")

	for i, peer := range nm.Peers {
		if (uflags&UAllowSingleHosts) == 0 && len(peer.AllowedIPs) < 2 {
			log.Printf("wgcfg: %v skipping a single-host peer.\n", peer.Key.ShortString())
			continue
		}
		if i > 0 {
			fmt.Fprintf(buf, "\n")
		}
		fmt.Fprintf(buf, "[Peer]\n")
		fmt.Fprintf(buf, "PublicKey = %s\n", base64.StdEncoding.EncodeToString(peer.Key[:]))
		var endpoints []string
		if peer.DERP != "" {
			endpoints = append(endpoints, peer.DERP)
		}
		endpoints = append(endpoints, peer.Endpoints...)
		if len(endpoints) > 0 {
			if len(endpoints) == 1 {
				fmt.Fprintf(buf, "Endpoint = %s", endpoints[0])
			} else if allEndpoints {
				// TODO(apenwarr): This mode is incompatible.
				// Normal wireguard clients don't know how to
				// parse it (yet?)
				fmt.Fprintf(buf, "Endpoint = %s",
					strings.Join(endpoints, ","))
			} else {
				fmt.Fprintf(buf, "Endpoint = %s # other endpoints: %s",
					endpoints[0],
					strings.Join(endpoints[1:], ", "))
			}
			buf.WriteByte('\n')
		}
		var aips []string
		for _, allowedIP := range peer.AllowedIPs {
			aip := allowedIP.String()
			if allowedIP.Mask == 0 {
				if (uflags & UAllowDefaultRoute) == 0 {
					log.Printf("wgcfg: %v skipping default route\n", peer.Key.ShortString())
					continue
				}
				if (uflags & UHackDefaultRoute) != 0 {
					aip = "10.0.0.0/8"
					log.Printf("wgcfg: %v converting default route => %v\n", peer.Key.ShortString(), aip)
				}
			} else if allowedIP.Mask < 32 {
				if (uflags & UAllowSubnetRoutes) == 0 {
					log.Printf("wgcfg: %v skipping subnet route\n", peer.Key.ShortString())
					continue
				}
			}
			aips = append(aips, aip)
		}
		fmt.Fprintf(buf, "AllowedIPs = %s\n", strings.Join(aips, ", "))
		if peer.KeepAlive {
			fmt.Fprintf(buf, "PersistentKeepalive = 25\n")
		}
	}

	return buf.String()
}
