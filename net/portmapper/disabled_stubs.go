// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build js
// +build js

package portmapper

import (
	"context"

	"tailscale.com/net/netaddr"
)

type upnpClient any

type uPnPDiscoResponse struct{}

func parseUPnPDiscoResponse([]byte) (uPnPDiscoResponse, error) {
	return uPnPDiscoResponse{}, nil
}

func (c *Client) getUPnPPortMapping(
	ctx context.Context,
	gw netaddr.IP,
	internal netaddr.IPPort,
	prevPort uint16,
) (external netaddr.IPPort, ok bool) {
	return netaddr.IPPort{}, false
}
