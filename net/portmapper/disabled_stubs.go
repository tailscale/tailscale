// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build js

package portmapper

import (
	"context"
	"net/netip"
)

type upnpClient any

type uPnPDiscoResponse struct{}

func parseUPnPDiscoResponse([]byte) (uPnPDiscoResponse, error) {
	return uPnPDiscoResponse{}, nil
}

func (c *Client) getUPnPPortMapping(
	ctx context.Context,
	gw netip.Addr,
	internal netip.AddrPort,
	prevPort uint16,
) (external netip.AddrPort, ok bool) {
	return netip.AddrPort{}, false
}
