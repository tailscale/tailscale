// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstun

import (
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// setLinkSpeed sets the advertised link speed of the TUN interface.
func setLinkSpeed(iface tun.Device, mbps int) error {
	name, err := iface.Name()
	if err != nil {
		return err
	}

	conn, err := genetlink.Dial(&netlink.Config{Strict: true})
	if err != nil {
		return err
	}

	defer conn.Close()

	f, err := conn.GetFamily(unix.ETHTOOL_GENL_NAME)
	if err != nil {
		return err
	}

	ae := netlink.NewAttributeEncoder()
	ae.Nested(unix.ETHTOOL_A_LINKMODES_HEADER, func(nae *netlink.AttributeEncoder) error {
		nae.String(unix.ETHTOOL_A_HEADER_DEV_NAME, name)
		return nil
	})
	ae.Uint32(unix.ETHTOOL_A_LINKMODES_SPEED, uint32(mbps))

	b, err := ae.Encode()
	if err != nil {
		return err
	}

	_, err = conn.Execute(
		genetlink.Message{
			Header: genetlink.Header{
				Command: unix.ETHTOOL_MSG_LINKMODES_SET,
				Version: unix.ETHTOOL_GENL_VERSION,
			},
			Data: b,
		},
		f.ID,
		netlink.Request|netlink.Acknowledge,
	)
	return err
}

// setLinkAttrs sets up link attributes that can be queried by external tools.
// Its failure is non-fatal to interface bringup.
func setLinkAttrs(iface tun.Device) error {
	// By default the link speed is 10Mbps, which is easily exceeded and causes monitoring tools to complain (#3933).
	return setLinkSpeed(iface, unix.SPEED_UNKNOWN)
}
