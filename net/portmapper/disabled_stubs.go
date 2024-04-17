// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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

func processUPnPResponses(metas []uPnPDiscoResponse) []uPnPDiscoResponse {
	return metas
}

func (c *Client) getUPnPPortMapping(
	ctx context.Context,
	gw netip.Addr,
	internal netip.AddrPort,
	prevPort uint16,
) (external netip.AddrPort, ok bool) {
	return netip.AddrPort{}, false
}
