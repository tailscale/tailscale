// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wakeonlan registers the Wake-on-LAN feature.
package wakeonlan

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/kortschak/wol"
	"golang.org/x/sync/errgroup"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
)

func init() {
	feature.Register("wakeonlan")
	ipnlocal.RegisterC2N("POST /wol", handleC2NWoL)
	ipnlocal.RegisterPeerAPIHandler("/v0/wol", handlePeerAPIWakeOnLAN)
	ipnlocal.RegisterPeerAPIHandler("/v0/check-direct", handlePeerAPICheckDirect)
	hostinfo.RegisterHostinfoNewHook(func(h *tailcfg.Hostinfo) {
		h.WoLMACs = getWoLMACs()
	})
}

func handleC2NWoL(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var macs []net.HardwareAddr
	for _, macStr := range r.Form["mac"] {
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			http.Error(w, "bad 'mac' param", http.StatusBadRequest)
			return
		}
		macs = append(macs, mac)
	}
	var res struct {
		SentTo []string
		Errors []string
	}
	st := b.NetMon().InterfaceState()
	if st == nil {
		res.Errors = append(res.Errors, "no interface state")
		writeJSON(w, &res)
		return
	}
	var password []byte // TODO(bradfitz): support? does anything use WoL passwords?
	for _, mac := range macs {
		for ifName, ips := range st.InterfaceIPs {
			for _, ip := range ips {
				if ip.Addr().IsLoopback() || ip.Addr().Is6() {
					continue
				}
				local := &net.UDPAddr{
					IP:   ip.Addr().AsSlice(),
					Port: 0,
				}
				remote := &net.UDPAddr{
					IP:   net.IPv4bcast,
					Port: 0,
				}
				if err := wol.Wake(mac, password, local, remote); err != nil {
					res.Errors = append(res.Errors, err.Error())
				} else {
					res.SentTo = append(res.SentTo, ifName)
				}
				break // one per interface is enough
			}
		}
	}
	sort.Strings(res.SentTo)
	writeJSON(w, &res)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func canWakeOnLAN(h ipnlocal.PeerAPIHandler) bool {
	if h.Peer().UnsignedPeerAPIOnly() {
		return false
	}
	return h.IsSelfUntagged() || h.PeerCaps().HasCapability(tailcfg.PeerCapabilityWakeOnLAN)
}

func canCheckDirect(h ipnlocal.PeerAPIHandler) bool {
	if h.Peer().UnsignedPeerAPIOnly() {
		return false
	}
	return h.IsSelfUntagged() || h.PeerCaps().HasCapability(tailcfg.PeerCapabilityWakeOnLAN)
}

func handlePeerAPICheckDirect(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	// metricCheckDirectCalls.Add(1)

	// Check capability
	if !canCheckDirect(h) {
		http.Error(w, "no check-direct access", http.StatusForbidden)
		return
	}

	// Validate method
	if r.Method != "POST" {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}

	// Get backend and netmap
	b := h.LocalBackend()
	nm := b.NetMap()
	if nm == nil {
		http.Error(w, "no netmap available", http.StatusServiceUnavailable)
		return
	}

	// Get local subnets
	localSubnets := getLocalSubnets(b)
	if len(localSubnets) == 0 {
		// No local network interfaces, return empty results
		writeJSON(w, &checkDirectResponse{})
		return
	}

	// Find peers with overlapping endpoints (excluding mobile)
	var candidateNodes []tailcfg.NodeView
	for _, peer := range nm.Peers {
		// Skip mobile devices - they can't be woken by WoL
		if hostinfo := peer.Hostinfo(); hostinfo.Valid() {
			os := hostinfo.OS()
			if os == "android" || os == "iOS" {
				continue
			}
		}

		// Check for endpoint overlap
		if peerHasOverlappingEndpoint(peer, localSubnets) {
			candidateNodes = append(candidateNodes, peer)
		}
	}

	// If no candidates found, return empty results
	if len(candidateNodes) == 0 {
		writeJSON(w, &checkDirectResponse{})
		return
	}

	// Ping candidates concurrently
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	type nodeResult struct {
		node   tailcfg.NodeView
		result *ipnstate.PingResult
		err    error
	}

	results := make([]nodeResult, len(candidateNodes))
	g, ctx := errgroup.WithContext(ctx)

	for i, node := range candidateNodes {
		i, node := i, node // capture loop variables
		g.Go(func() error {
			// Get first Tailscale IP to ping
			addrs := node.Addresses()
			if addrs.Len() == 0 {
				results[i] = nodeResult{node: node, err: errors.New("no addresses")}
				return nil
			}
			ip := addrs.At(0).Addr()

			// Ping with disco protocol
			pr, err := b.Ping(ctx, ip, tailcfg.PingDisco, 0)
			results[i] = nodeResult{node: node, result: pr, err: err}
			return nil // Individual failures don't abort entire operation
		})
	}

	g.Wait() // Wait for all pings to complete (or timeout)

	// Process results and build response
	var resp checkDirectResponse
	for _, res := range results {
		// Skip nodes without direct connections
		if res.result == nil || res.result.Endpoint == "" {
			continue
		}

		// Parse endpoint address
		endpointAddrPort, err := netip.ParseAddrPort(res.result.Endpoint)
		if err != nil {
			continue
		}

		onSameSubnet := isOnSameSubnet(endpointAddrPort.Addr(), localSubnets)
		if !onSameSubnet {
			continue
		}

		// Build response entry
		info := directNodeInfo{
			NodeID:   res.node.StableID(),
			NodeName: res.node.Name(),
			Endpoint: res.result.Endpoint,
			Latency:  res.result.LatencySeconds,
		}

		resp.Nodes = append(resp.Nodes, info)
	}
	resp.SelfMacAddresses = getWoLMACs()

	writeJSON(w, resp)
}

var metricWakeOnLANCalls = clientmetric.NewCounter("peerapi_wol")

// metricCheckDirectCalls = clientmetric.NewCounter("peerapi_check_direct")

func handlePeerAPIWakeOnLAN(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	metricWakeOnLANCalls.Add(1)
	if !canWakeOnLAN(h) {
		http.Error(w, "no WoL access", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
	macStr := r.FormValue("mac")
	if macStr == "" {
		http.Error(w, "missing 'mac' param", http.StatusBadRequest)
		return
	}
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		http.Error(w, "bad 'mac' param", http.StatusBadRequest)
		return
	}
	var password []byte // TODO(bradfitz): support? does anything use WoL passwords?
	st := h.LocalBackend().NetMon().InterfaceState()
	if st == nil {
		http.Error(w, "failed to get interfaces state", http.StatusInternalServerError)
		return
	}
	var res struct {
		SentTo []string
		Errors []string
	}
	for ifName, ips := range st.InterfaceIPs {
		for _, ip := range ips {
			if ip.Addr().IsLoopback() || ip.Addr().Is6() {
				continue
			}
			local := &net.UDPAddr{
				IP:   ip.Addr().AsSlice(),
				Port: 0,
			}
			remote := &net.UDPAddr{
				IP:   net.IPv4bcast,
				Port: 0,
			}
			if err := wol.Wake(mac, password, local, remote); err != nil {
				res.Errors = append(res.Errors, err.Error())
			} else {
				res.SentTo = append(res.SentTo, ifName)
			}
			break // one per interface is enough
		}
	}
	sort.Strings(res.SentTo)
	writeJSON(w, res)
}

type checkDirectResponse struct {
	Nodes            []directNodeInfo `json:"nodes"`
	SelfMacAddresses []string         `json:"self_mac_addresses"`
}

type directNodeInfo struct {
	NodeID       tailcfg.StableNodeID `json:"nodeID"`
	NodeName     string               `json:"nodeName,omitempty"`
	Endpoint     string               `json:"endpoint"`
	OnSameSubnet bool                 `json:"onSameSubnet"`
	Latency      float64              `json:"latencySeconds"`
}

func getLocalSubnets(b *ipnlocal.LocalBackend) []netip.Prefix {
	st := b.NetMon().InterfaceState()
	if st == nil || st.InterfaceIPs == nil {
		return nil
	}

	var subnets []netip.Prefix
	for _, prefixes := range st.InterfaceIPs {
		for _, prefix := range prefixes {
			// Skip loopback
			if prefix.Addr().IsLoopback() {
				continue
			}
			// Skip Tailscale CGNAT range (100.64.0.0/10)
			if prefix.Addr().IsPrivate() && prefix.Bits() >= 10 {
				// Check if it's in the Tailscale CGNAT range
				if prefix.Addr().Is4() {
					ip := prefix.Addr().As4()
					// 100.64.0.0/10 means first byte is 100 and second byte is 64-127
					if ip[0] == 100 && ip[1] >= 64 && ip[1] < 128 {
						continue
					}
				}
			}
			subnets = append(subnets, prefix)
		}
	}
	return subnets
}

func peerHasOverlappingEndpoint(peer tailcfg.NodeView, localSubnets []netip.Prefix) bool {
	endpoints := peer.Endpoints()
	for i := range endpoints.Len() {
		epAddrPort := endpoints.At(i)
		epAddr := epAddrPort.Addr()

		// Check if this endpoint IP is in any local subnet
		for _, localSubnet := range localSubnets {
			// Match IP families
			if localSubnet.Addr().Is4() != epAddr.Is4() {
				continue
			}
			if localSubnet.Contains(epAddr) {
				return true
			}
		}
	}
	return false
}

func isOnSameSubnet(endpointIP netip.Addr, localSubnets []netip.Prefix) bool {
	for _, localSubnet := range localSubnets {
		// Match IP families
		if localSubnet.Addr().Is4() != endpointIP.Is4() {
			continue
		}
		if localSubnet.Contains(endpointIP) {
			return true
		}
	}
	return false
}

// TODO(bradfitz): this is all too simplistic and static. It needs to run
// continuously in response to netmon events (USB ethernet adapters might get
// plugged in) and look for the media type/status/etc. Right now on macOS it
// still detects a half dozen "up" en0, en1, en2, en3 etc interfaces that don't
// have any media. We should only report the one that's actually connected.
// But it works for now (2023-10-05) for fleshing out the rest.

var wakeMAC = envknob.RegisterString("TS_WAKE_MAC") // mac address, "false" or "auto". for https://github.com/tailscale/tailscale/issues/306

// getWoLMACs returns up to 10 MAC address of the local machine to send
// wake-on-LAN packets to in order to wake it up. The returned MACs are in
// lowercase hex colon-separated form ("xx:xx:xx:xx:xx:xx").
//
// If TS_WAKE_MAC=auto, it tries to automatically find the MACs based on the OS
// type and interface properties. (TODO(bradfitz): incomplete) If TS_WAKE_MAC is
// set to a MAC address, that sole MAC address is returned.
func getWoLMACs() (macs []string) {
	switch runtime.GOOS {
	case "ios", "android":
		return nil
	}
	if s := wakeMAC(); s != "" {
		switch s {
		case "auto":
			ifs, _ := net.Interfaces()
			for _, iface := range ifs {
				if iface.Flags&net.FlagLoopback != 0 {
					continue
				}
				if iface.Flags&net.FlagBroadcast == 0 ||
					iface.Flags&net.FlagRunning == 0 ||
					iface.Flags&net.FlagUp == 0 {
					continue
				}
				if keepMAC(iface.Name, iface.HardwareAddr) {
					macs = append(macs, iface.HardwareAddr.String())
				}
				if len(macs) == 10 {
					break
				}
			}
			return macs
		case "false", "off": // fast path before ParseMAC error
			return nil
		}
		mac, err := net.ParseMAC(s)
		if err != nil {
			log.Printf("invalid MAC %q", s)
			return nil
		}
		return []string{mac.String()}
	}
	return nil
}

var ignoreWakeOUI = map[[3]byte]bool{
	{0x00, 0x15, 0x5d}: true, // Hyper-V
	{0x00, 0x50, 0x56}: true, // VMware
	{0x00, 0x1c, 0x14}: true, // VMware
	{0x00, 0x05, 0x69}: true, // VMware
	{0x00, 0x0c, 0x29}: true, // VMware
	{0x00, 0x1c, 0x42}: true, // Parallels
	{0x08, 0x00, 0x27}: true, // VirtualBox
	{0x00, 0x21, 0xf6}: true, // VirtualBox
	{0x00, 0x14, 0x4f}: true, // VirtualBox
	{0x00, 0x0f, 0x4b}: true, // VirtualBox
	{0x52, 0x54, 0x00}: true, // VirtualBox/Vagrant
}

func keepMAC(ifName string, mac []byte) bool {
	if len(mac) != 6 {
		return false
	}
	base := strings.TrimRightFunc(ifName, unicode.IsNumber)
	switch runtime.GOOS {
	case "darwin":
		switch base {
		case "llw", "awdl", "utun", "bridge", "lo", "gif", "stf", "anpi", "ap":
			return false
		}
	}
	if mac[0] == 0x02 && mac[1] == 0x42 {
		// Docker container.
		return false
	}
	oui := [3]byte{mac[0], mac[1], mac[2]}
	if ignoreWakeOUI[oui] {
		return false
	}
	return true
}
