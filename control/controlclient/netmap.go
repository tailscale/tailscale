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
	"net"
	"runtime"
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
	Peers         []tailcfg.Node
	DNS           []wgcfg.IP
	DNSDomains    []string
	Hostinfo      tailcfg.Hostinfo
	PacketFilter  filter.Matches

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

func keyString(key [32]byte) string {
	b64 := base64.StdEncoding.EncodeToString(key[:])
	abbrev := "invalid"
	if len(b64) == 44 {
		abbrev = b64[0:4] + "…" + b64[39:43]
	}
	return fmt.Sprintf("[%s]", abbrev)
}

func (nm *NetworkMap) Concise() string {
	buf := new(strings.Builder)
	fmt.Fprintf(buf, "NetworkMap: self: %v auth=%v :%v %v\n",
		keyString(nm.NodeKey), nm.MachineStatus,
		nm.LocalPort, nm.Addresses)
	for _, p := range nm.Peers {
		aip := make([]string, len(p.AllowedIPs))
		for i, a := range p.AllowedIPs {
			aip[i] = fmt.Sprint(a)
		}
		u := fmt.Sprint(p.User)
		if strings.HasPrefix(u, "userid:") {
			u = "u:" + u[7:]
		}
		f1 := fmt.Sprintf(" %v %-6v %v",
			keyString(p.Key), u, p.Endpoints)
		f2 := fmt.Sprintf(" %*v\n", 70-len(f1),
			strings.Join(aip, " "))
		fmt.Fprintf(buf, "%s%s", f1, f2)
	}
	return buf.String()
}

func (nm *NetworkMap) JSON() string {
	b, err := json.MarshalIndent(*nm, "", "  ")
	if err != nil {
		return fmt.Sprintf("[json error: %v]", err)
	}
	return string(b)
}

// TODO(apenwarr): delete me once relaynode doesn't need this anymore.
// control.go:userMap() supercedes it. This does not belong in the client.
func (nm *NetworkMap) UserMap() map[string][]filter.IP {
	// Make a lookup table of roles
	log.Printf("roles list is: %v\n", nm.Roles)
	roles := make(map[tailcfg.RoleID]tailcfg.Role)
	for _, role := range nm.Roles {
		roles[role.ID] = role
	}

	// First, go through each node's addresses and make a lookup table
	// of IP->User.
	fwd := make(map[wgcfg.IP]string)
	for _, node := range nm.Peers {
		for _, addr := range node.Addresses {
			if addr.Mask == 32 && addr.IP.Is4() {
				user, ok := nm.UserProfiles[node.User]
				if ok {
					fwd[addr.IP] = user.LoginName
				}
			}
		}
	}

	// Next, reverse the mapping into User->IP.
	rev := make(map[string][]filter.IP)
	for ip, username := range fwd {
		ip4 := ip.To4()
		if ip4 != nil {
			fip := filter.NewIP(net.IP(ip4))
			rev[username] = append(rev[username], fip)
		}
	}

	// Now add roles, which are lists of users, and therefore lists
	// of those users' IP addresses.
	for _, user := range nm.UserProfiles {
		for _, roleid := range user.Roles {
			role, ok := roles[roleid]
			if ok {
				rolename := "role:" + role.Name
				rev[rolename] = append(rev[rolename], rev[user.LoginName]...)
			}
		}
	}

	//log.Printf("Usermap is: %v\n", rev)
	return rev
}

var iOS = runtime.GOOS == "darwin" && (runtime.GOARCH == "arm" || runtime.GOARCH == "arm64")
var keepalive = !iOS

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

// TODO(apenwarr): This mode is dangerous.
// Discarding the extra endpoints is almost universally the wrong choice.
// Except that plain wireguard can't handle a peer with multiple endpoints.
// (Yet?)
func (nm *NetworkMap) WireGuardConfigOneEndpoint(uflags int, dnsOverride []wgcfg.IP) string {
	return nm._WireGuardConfig(uflags, dnsOverride, false)
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
			log.Printf("wgcfg: %v skipping a single-host peer.\n", peer.Key.AbbrevString())
			continue
		}
		if i > 0 {
			fmt.Fprintf(buf, "\n")
		}
		fmt.Fprintf(buf, "[Peer]\n")
		fmt.Fprintf(buf, "PublicKey = %s\n", base64.StdEncoding.EncodeToString(peer.Key[:]))
		if len(peer.Endpoints) > 0 {
			if len(peer.Endpoints) == 1 {
				fmt.Fprintf(buf, "Endpoint = %s", peer.Endpoints[0])
			} else if allEndpoints {
				// TODO(apenwarr): This mode is incompatible.
				// Normal wireguard clients don't know how to
				// parse it (yet?)
				fmt.Fprintf(buf, "Endpoint = %s",
					strings.Join(peer.Endpoints, ","))
			} else {
				fmt.Fprintf(buf, "Endpoint = %s # other endpoints: %s",
					peer.Endpoints[0],
					strings.Join(peer.Endpoints[1:], ", "))
			}
			buf.WriteByte('\n')
		}
		var aips []string
		for _, allowedIP := range peer.AllowedIPs {
			aip := allowedIP.String()
			if allowedIP.Mask == 0 {
				if (uflags & UAllowDefaultRoute) == 0 {
					log.Printf("wgcfg: %v skipping default route\n", peer.Key.AbbrevString())
					continue
				}
				if (uflags & UHackDefaultRoute) != 0 {
					aip = "10.0.0.0/8"
					log.Printf("wgcfg: %v converting default route => %v\n", peer.Key.AbbrevString(), aip)
				}
			} else if allowedIP.Mask < 32 {
				if (uflags & UAllowSubnetRoutes) == 0 {
					log.Printf("wgcfg: %v skipping subnet route\n", peer.Key.AbbrevString())
					continue
				}
			}
			aips = append(aips, aip)
		}
		fmt.Fprintf(buf, "AllowedIPs = %s\n", strings.Join(aips, ", "))
		if keepalive {
			fmt.Fprintf(buf, "PersistentKeepalive = 25\n")
		}
	}

	return buf.String()
}
