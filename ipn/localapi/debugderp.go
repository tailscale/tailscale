// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package localapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
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

	if reg.Avoid {
		st.Warnings = append(st.Warnings, "Region is marked with Avoid bit")
	}
	if len(reg.Nodes) == 0 {
		st.Errors = append(st.Errors, "Region has no nodes defined")
		return
	}

	// TODO(bradfitz): finish:
	// * first try TCP connection
	// * reconnect 4 or 5 times; see if we ever get a different server key.
	//   if so, they're load balancing the wrong way. error.
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
	// * try STUN queries
	// * warn about IPv6 only
	// * If their certificate is bad, either expired or just wrongly
	//   issued in the first place, tell them specifically that the
	// 	 cert is bad not just that the connection failed.
	// * If /generate_204 on port 80 cannot be reached, warn
	// 	 that they won't get captive portal detection and
	// 	 should allow port 80.
	// * If they have exactly one DERP region because they
	//   removed all of Tailscale's DERPs, warn that they have
	//   a SPOF that will hamper even direct connections from
	//   working. (warning, not error, as that's probably a likely
	//   config for headscale users)
	st.Info = append(st.Info, "TODO: 🦉")
}
