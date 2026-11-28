// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wakeonlan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/localapi"
	"tailscale.com/tailcfg"
	"tailscale.com/util/httpm"
)

// serveLocalAPIWakeOnLAN handles POST /localapi/v0/wake-on-lan.
//
// The "target" query parameter is either a MAC address or the name or
// Tailscale IP of a node whose advertised Wake-on-LAN MACs should be woken.
// The optional "via" query parameter names a peer on the target's LAN that
// should broadcast the magic packets. If "via" is empty, they're broadcast
// from this node.
func serveLocalAPIWakeOnLAN(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "wake-on-lan access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	b := h.LocalBackend()
	nb := b.NodeBackend()

	macs, err := resolveTargetMACs(nb, r.FormValue("target"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	via := nb.Self()
	if v := r.FormValue("via"); v != "" {
		var ok bool
		via, ok = findNode(nb, v)
		if !ok {
			http.Error(w, fmt.Sprintf("no device %q found in your tailnet", v), http.StatusBadRequest)
			return
		}
	}

	res := &apitype.WakeOnLANResponse{Via: nodeShortName(via)}
	for _, mac := range macs {
		res.MACs = append(res.MACs, mac.String())
	}
	if !via.Valid() || via.ID() == nb.Self().ID() {
		st := b.NetMon().InterfaceState()
		if st == nil {
			http.Error(w, "failed to get interfaces state", http.StatusInternalServerError)
			return
		}
		for _, mac := range macs {
			sentTo, errs := broadcastMagicPacket(st, mac)
			res.SentTo = append(res.SentTo, sentTo...)
			res.Errors = append(res.Errors, errs...)
		}
	} else {
		base := nb.PeerAPIBase(via)
		if base == "" {
			http.Error(w, fmt.Sprintf("device %q is offline or does not support Wake-on-LAN relaying", res.Via), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		tr := b.Dialer().PeerAPITransport()
		for _, mac := range macs {
			sentTo, errs := wakeViaPeer(ctx, tr, base, mac)
			res.SentTo = append(res.SentTo, sentTo...)
			res.Errors = append(res.Errors, errs...)
		}
	}
	sort.Strings(res.SentTo)
	res.SentTo = uniq(res.SentTo)
	writeJSON(w, res)
}

// resolveTargetMACs returns the MAC addresses to wake for target, which is
// either a MAC address or the name or Tailscale IP of a node that advertises
// its Wake-on-LAN MACs in its Hostinfo.
func resolveTargetMACs(nb ipnext.NodeBackend, target string) ([]net.HardwareAddr, error) {
	if target == "" {
		return nil, errors.New("missing 'target' param")
	}
	if mac, err := net.ParseMAC(target); err == nil {
		return []net.HardwareAddr{mac}, nil
	}
	n, ok := findNode(nb, target)
	if !ok {
		return nil, fmt.Errorf("%q is not a MAC address or a device in your tailnet", target)
	}
	var macs []net.HardwareAddr
	if hi := n.Hostinfo(); hi.Valid() {
		for _, s := range hi.WoLMACs().All() {
			if mac, err := net.ParseMAC(s); err == nil {
				macs = append(macs, mac)
			}
		}
	}
	if len(macs) == 0 {
		return nil, fmt.Errorf("device %q has not advertised any Wake-on-LAN MAC addresses; run tailscaled on it with TS_WAKE_MAC=auto (or TS_WAKE_MAC=<mac>), or pass its MAC address directly", nodeShortName(n))
	}
	return macs, nil
}

// findNode returns the node (self or a peer) whose Tailscale IP, MagicDNS
// name, or short hostname matches s.
func findNode(nb ipnext.NodeBackend, s string) (_ tailcfg.NodeView, ok bool) {
	if ip, err := netip.ParseAddr(s); err == nil {
		id, ok := nb.NodeByAddr(ip)
		if !ok {
			return tailcfg.NodeView{}, false
		}
		return nb.NodeByID(id)
	}
	match := func(n tailcfg.NodeView) bool {
		return n.Valid() && nodeNameMatches(n, s)
	}
	if self := nb.Self(); match(self) {
		return self, true
	}
	peers := nb.AppendMatchingPeers(nil, match)
	if len(peers) == 0 {
		return tailcfg.NodeView{}, false
	}
	return peers[0], true
}

// nodeNameMatches reports whether s names n, either by its full MagicDNS
// name (with or without the trailing dot), its first DNS label, or its
// computed display name.
func nodeNameMatches(n tailcfg.NodeView, s string) bool {
	s = strings.TrimSuffix(s, ".")
	full := strings.TrimSuffix(n.Name(), ".")
	return strings.EqualFold(full, s) ||
		strings.EqualFold(nodeShortName(n), s) ||
		strings.EqualFold(n.ComputedName(), s)
}

// nodeShortName returns the first label of n's MagicDNS name.
func nodeShortName(n tailcfg.NodeView) string {
	if !n.Valid() {
		return ""
	}
	name, _, _ := strings.Cut(n.Name(), ".")
	if name == "" {
		return n.ComputedName()
	}
	return name
}

// wakeViaPeer asks the peer whose PeerAPI is at base to broadcast a magic
// packet for mac on its LANs.
func wakeViaPeer(ctx context.Context, tr http.RoundTripper, base string, mac net.HardwareAddr) (sentTo, errs []string) {
	body := url.Values{"mac": {mac.String()}}.Encode()
	req, err := http.NewRequestWithContext(ctx, httpm.POST, base+"/v0/wol", strings.NewReader(body))
	if err != nil {
		return nil, []string{err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := tr.RoundTrip(req)
	if err != nil {
		return nil, []string{err.Error()}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 1<<10))
		return nil, []string{fmt.Sprintf("peer returned %v: %s", res.Status, strings.TrimSpace(string(msg)))}
	}
	var pr struct {
		SentTo []string
		Errors []string
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&pr); err != nil {
		return nil, []string{err.Error()}
	}
	return pr.SentTo, pr.Errors
}

// uniq removes adjacent duplicates from the sorted slice s.
func uniq(s []string) []string {
	if len(s) < 2 {
		return s
	}
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
