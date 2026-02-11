// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package preftype

import (
	"errors"
	"fmt"
)

// LinuxPacketMarks holds the packet mark configuration for Linux packet
// marking used in firewall rules and routing. When this struct is nil in Prefs,
// the default values from tsconst are used.
type LinuxPacketMarks struct {
	// FwmarkMask is the mask for reading/writing firewall mark bits on a packet.
	// Must be non-zero if set. Default is 0xff0000.
	FwmarkMask uint32

	// SubnetRouteMark is the mark value for packets from Tailscale to subnet
	// route destinations. Must be non-zero and must be covered by FwmarkMask.
	// Default is 0x40000.
	SubnetRouteMark uint32

	// BypassMark is the mark value for packets originated by tailscaled that
	// must not be routed over the Tailscale network. Must be non-zero, must be
	// covered by FwmarkMask, and must differ from SubnetRouteMark.
	// Default is 0x80000.
	BypassMark uint32
}

// Validate checks that the mark values are valid.
// It returns an error if any validation fails.
func (m *LinuxPacketMarks) Validate() error {
	if m == nil {
		return nil
	}
	if m.FwmarkMask == 0 {
		return errors.New("fwmark mask must be non-zero")
	}
	if m.SubnetRouteMark == 0 {
		return errors.New("subnet route mark must be non-zero")
	}
	if m.BypassMark == 0 {
		return errors.New("bypass mark must be non-zero")
	}
	if (m.SubnetRouteMark & m.FwmarkMask) != m.SubnetRouteMark {
		return fmt.Errorf("subnet route mark (0x%x) must be covered by fwmark mask (0x%x)", m.SubnetRouteMark, m.FwmarkMask)
	}
	if (m.BypassMark & m.FwmarkMask) != m.BypassMark {
		return fmt.Errorf("bypass mark (0x%x) must be covered by fwmark mask (0x%x)", m.BypassMark, m.FwmarkMask)
	}
	if m.SubnetRouteMark == m.BypassMark {
		return errors.New("subnet route mark and bypass mark must differ")
	}
	return nil
}

func (m *LinuxPacketMarks) Equals(m2 *LinuxPacketMarks) bool {
	if m == m2 {
		return true
	}
	if m == nil || m2 == nil {
		return false
	}
	return m.FwmarkMask == m2.FwmarkMask &&
		m.SubnetRouteMark == m2.SubnetRouteMark &&
		m.BypassMark == m2.BypassMark
}
