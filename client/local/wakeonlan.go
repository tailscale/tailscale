// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_wakeonlan

package local

import (
	"context"
	"net/http"
	"net/url"

	"tailscale.com/client/tailscale/apitype"
)

// WakeOnLAN sends Wake-on-LAN magic packets to wake target.
//
// The target is either a MAC address or the name or Tailscale IP of a device
// in the tailnet that advertises its Wake-on-LAN MAC addresses (see
// TS_WAKE_MAC). If via is empty, the packets are broadcast from this machine's
// LANs. Otherwise via is the name or Tailscale IP of an awake peer on the
// target's LAN, which broadcasts the packets on its LANs instead.
//
// API maturity: this method is not considered a stable API and is subject to change between releases.
func (lc *Client) WakeOnLAN(ctx context.Context, target, via string) (*apitype.WakeOnLANResponse, error) {
	v := url.Values{"target": {target}}
	if via != "" {
		v.Set("via", via)
	}
	body, err := lc.send(ctx, "POST", "/localapi/v0/wake-on-lan?"+v.Encode(), http.StatusOK, nil)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*apitype.WakeOnLANResponse](body)
}
