// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package localapi

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netns"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/nettype"
)

func (h *Handler) serveDebugDERPRegion(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var st ipnstate.DebugDERPRegionReport
	defer func() {
		j, _ := json.Marshal(st)
		w.Header().Set("Content-Type", "application/json")
		w.Write(j)
	}()

	dm := h.b.DERPMap()
	if dm == nil {
		st.Errors = append(st.Errors, "no DERP map (not connected?)")
		return
	}
	regStr := r.FormValue("region")
	var reg *tailcfg.DERPRegion
	if id, err := strconv.Atoi(regStr); err == nil {
		reg = dm.Regions[id]
	} else {
		for _, r := range dm.Regions {
			if r.RegionCode == regStr {
				reg = r
				break
			}
		}
	}
	if reg == nil {
		st.Errors = append(st.Errors, fmt.Sprintf("no such region %q in DERP map", regStr))
		return
	}
	st.Info = append(st.Info, fmt.Sprintf("Region %v == %q", reg.RegionID, reg.RegionCode))
	if len(dm.Regions) == 1 {
		st.Warnings = append(st.Warnings, "Having only a single DERP region (i.e. removing the default Tailscale-provided regions) is a single point of failure and could hamper connectivity")
	}

	if reg.Avoid {
		st.Warnings = append(st.Warnings, "Region is marked with Avoid bit")
	}
	if len(reg.Nodes) == 0 {
		st.Errors = append(st.Errors, "Region has no nodes defined")
		return
	}

	ctx := r.Context()

	var (
		dialer net.Dialer
		client *http.Client = http.DefaultClient
	)
	checkConn := func(derpNode *tailcfg.DERPNode) bool {
		port := cmp.Or(derpNode.DERPPort, 443)

		var (
			hasIPv4 bool
			hasIPv6 bool
		)

		// Check IPv4 first
		addr := net.JoinHostPort(cmp.Or(derpNode.IPv4, derpNode.HostName), strconv.Itoa(port))
		conn, err := dialer.DialContext(ctx, "tcp4", addr)
		if err != nil {
			st.Errors = append(st.Errors, fmt.Sprintf("Error connecting to node %q @ %q over IPv4: %v", derpNode.HostName, addr, err))
		} else {
			defer conn.Close()

			// Upgrade to TLS and verify that works properly.
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName: cmp.Or(derpNode.CertName, derpNode.HostName),
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				st.Errors = append(st.Errors, fmt.Sprintf("Error upgrading connection to node %q @ %q to TLS over IPv4: %v", derpNode.HostName, addr, err))
			} else {
				hasIPv4 = true
			}
		}

		// Check IPv6
		addr = net.JoinHostPort(cmp.Or(derpNode.IPv6, derpNode.HostName), strconv.Itoa(port))
		conn, err = dialer.DialContext(ctx, "tcp6", addr)
		if err != nil {
			st.Errors = append(st.Errors, fmt.Sprintf("Error connecting to node %q @ %q over IPv6: %v", derpNode.HostName, addr, err))
		} else {
			defer conn.Close()

			// Upgrade to TLS and verify that works properly.
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName: cmp.Or(derpNode.CertName, derpNode.HostName),
				// TODO(andrew-d): we should print more
				// detailed failure information on if/why TLS
				// verification fails
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				st.Errors = append(st.Errors, fmt.Sprintf("Error upgrading connection to node %q @ %q to TLS over IPv6: %v", derpNode.HostName, addr, err))
			} else {
				hasIPv6 = true
			}
		}

		// If we only have an IPv6 conn, then warn; we want both.
		if hasIPv6 && !hasIPv4 {
			st.Warnings = append(st.Warnings, fmt.Sprintf("Node %q only has IPv6 connectivity, not IPv4", derpNode.HostName))
		} else if hasIPv6 && hasIPv4 {
			st.Info = append(st.Info, fmt.Sprintf("Node %q has working IPv4 and IPv6 connectivity", derpNode.HostName))
		}

		return hasIPv4 || hasIPv6
	}

	checkSTUN4 := func(derpNode *tailcfg.DERPNode) {
		u4, err := nettype.MakePacketListenerWithNetIP(netns.Listener(h.logf, h.b.NetMon())).ListenPacket(ctx, "udp4", ":0")
		if err != nil {
			st.Errors = append(st.Errors, fmt.Sprintf("Error creating IPv4 STUN listener: %v", err))
			return
		}
		defer u4.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var addr netip.Addr
		if derpNode.IPv4 != "" {
			addr, err = netip.ParseAddr(derpNode.IPv4)
			if err != nil {
				// Error printed elsewhere
				return
			}
		} else {
			addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", derpNode.HostName)
			if err != nil {
				st.Errors = append(st.Errors, fmt.Sprintf("Error resolving node %q IPv4 addresses: %v", derpNode.HostName, err))
				return
			}
			addr = addrs[0]
		}

		addrPort := netip.AddrPortFrom(addr, uint16(cmp.Or(derpNode.STUNPort, 3478)))

		txID := stun.NewTxID()
		req := stun.Request(txID)

		done := make(chan struct{})
		defer close(done)

		go func() {
			select {
			case <-ctx.Done():
			case <-done:
			}
			u4.Close()
		}()

		gotResponse := make(chan netip.AddrPort, 1)
		go func() {
			defer u4.Close()

			var buf [64 << 10]byte
			for {
				n, addr, err := u4.ReadFromUDPAddrPort(buf[:])
				if err != nil {
					return
				}
				pkt := buf[:n]
				if !stun.Is(pkt) {
					continue
				}
				ap := netaddr.Unmap(addr)
				if !ap.IsValid() {
					continue
				}
				tx, addrPort, err := stun.ParseResponse(pkt)
				if err != nil {
					continue
				}
				if tx == txID {
					gotResponse <- addrPort
					return
				}
			}
		}()

		_, err = u4.WriteToUDPAddrPort(req, addrPort)
		if err != nil {
			st.Errors = append(st.Errors, fmt.Sprintf("Error sending IPv4 STUN packet to %v (%q): %v", addrPort, derpNode.HostName, err))
			return
		}

		select {
		case resp := <-gotResponse:
			st.Info = append(st.Info, fmt.Sprintf("Node %q returned IPv4 STUN response: %v", derpNode.HostName, resp))
		case <-ctx.Done():
			st.Warnings = append(st.Warnings, fmt.Sprintf("Node %q did not return a IPv4 STUN response", derpNode.HostName))
		}
	}

	// Start by checking whether we can establish a HTTP connection
	for _, derpNode := range reg.Nodes {
		if !derpNode.STUNOnly {
			connSuccess := checkConn(derpNode)

			// Verify that the /generate_204 endpoint works
			captivePortalURL := fmt.Sprintf("http://%s/generate_204?t=%d", derpNode.HostName, time.Now().Unix())
			req, err := http.NewRequest("GET", captivePortalURL, nil)
			if err != nil {
				st.Warnings = append(st.Warnings, fmt.Sprintf("Internal error creating request for captive portal check: %v", err))
				continue
			}
			req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate, no-transform, max-age=0")
			resp, err := client.Do(req)
			if err != nil {
				st.Warnings = append(st.Warnings, fmt.Sprintf("Error making request to the captive portal check %q; is port 80 blocked?", captivePortalURL))
			} else {
				resp.Body.Close()
			}

			if !connSuccess {
				continue
			}

			fakePrivKey := key.NewNode()

			// Next, repeatedly get the server key to see if the node is
			// behind a load balancer (incorrectly).
			serverPubKeys := make(map[key.NodePublic]bool)
			for i := range 5 {
				func() {
					rc := derphttp.NewRegionClient(fakePrivKey, h.logf, h.b.NetMon(), func() *tailcfg.DERPRegion {
						return &tailcfg.DERPRegion{
							RegionID:   reg.RegionID,
							RegionCode: reg.RegionCode,
							RegionName: reg.RegionName,
							Nodes:      []*tailcfg.DERPNode{derpNode},
						}
					})
					if err := rc.Connect(ctx); err != nil {
						st.Errors = append(st.Errors, fmt.Sprintf("Error connecting to node %q @ try %d: %v", derpNode.HostName, i, err))
						return
					}

					if len(serverPubKeys) == 0 {
						st.Info = append(st.Info, fmt.Sprintf("Successfully established a DERP connection with node %q", derpNode.HostName))
					}
					serverPubKeys[rc.ServerPublicKey()] = true
				}()
			}
			if len(serverPubKeys) > 1 {
				st.Errors = append(st.Errors, fmt.Sprintf("Received multiple server public keys (%d); is the DERP server behind a load balancer?", len(serverPubKeys)))
			}
		} else {
			st.Info = append(st.Info, fmt.Sprintf("Node %q is marked STUNOnly; skipped non-STUN checks", derpNode.HostName))
		}

		// Send a STUN query to this node to verify whether or not it
		// correctly returns an IP address.
		checkSTUN4(derpNode)
	}

	// TODO(bradfitz): finish:
	// * try to DERP auth with new public key.
	// * if rejected, add Info that it's likely the DERP server authz is on,
	//   try with LocalBackend's node key instead.
	// * if they have more then one node, try to relay a packet between them
	//   and see if it works (like cmd/derpprobe). But if server authz is on,
	//   we won't be able to, so just warn. Say to turn that off, try again,
	//   then turn it back on. TODO(bradfitz): maybe add a debug frame to DERP
	//   protocol to say how many peers it's meshed with. Should match count
	//   in DERPRegion. Or maybe even list all their server pub keys that it's peered
	//   with.
	// * If their certificate is bad, either expired or just wrongly
	//   issued in the first place, tell them specifically that the
	// 	 cert is bad not just that the connection failed.
}
