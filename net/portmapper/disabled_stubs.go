// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build ios
// (https://github.com/tailscale/tailscale/issues/2495)

package portmapper

import (
	"context"

	"inet.af/netaddr"
)

type upnpClient interface{}

func getUPnPClient(ctx context.Context, gw netaddr.IP) (upnpClient, error) {
	return nil, nil
}

func (c *Client) getUPnPPortMapping(
	ctx context.Context,
	gw netaddr.IP,
	internal netaddr.IPPort,
	prevPort uint16,
) (external netaddr.IPPort, ok bool) {
	return netaddr.IPPort{}, false
}
