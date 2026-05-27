// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_gro

package tstun

import (
	"errors"
	"net/netip"
	"runtime"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
)

// SetLinkFeaturesPostUp configures link features on t based on select TS_TUN_
// environment variables, control-plane node attributes (via knobs, which may be
// nil), and OS feature tests. Callers should ensure t is up prior to calling,
// otherwise OS feature tests may be inconclusive.
func (t *Wrapper) SetLinkFeaturesPostUp(knobs *controlknobs.Knobs) {
	if t.isTAP || runtime.GOOS == "android" {
		return
	}
	if groDev, ok := t.tdev.(tun.GRODevice); ok {
		if envknob.Bool("TS_TUN_DISABLE_UDP_GRO") ||
			(knobs != nil && knobs.DisableTUNUDPGRO.Load()) {
			groDev.DisableUDPGRO()
		}
		if envknob.Bool("TS_TUN_DISABLE_TCP_GRO") ||
			(knobs != nil && knobs.DisableTUNTCPGRO.Load()) {
			groDev.DisableTCPGRO()
		}
		err := probeTCPGRO(groDev)
		if errors.Is(err, unix.EINVAL) {
			groDev.DisableTCPGRO()
			groDev.DisableUDPGRO()
			t.logf("disabled TUN TCP & UDP GRO due to GRO probe error: %v", err)
		}
	}
}

// ApplyGROKnobs applies the [tailcfg.NodeAttrDisableTUNUDPGRO] and
// [tailcfg.NodeAttrDisableTUNTCPGRO] knob values (via knobs, which must be
// non-nil) to t's underlying device. It is intended to be called when a
// control-plane node attribute change is detected after [SetLinkFeaturesPostUp]
// has already run.
//
// Note: wireguard-go's GRO disablement is one-way (sticky); ApplyGROKnobs can
// move TUN UDP/TCP GRO from enabled to disabled, but the reverse requires a
// client restart.
func (t *Wrapper) ApplyGROKnobs(knobs *controlknobs.Knobs) {
	if t.isTAP || runtime.GOOS == "android" || knobs == nil {
		return
	}
	groDev, ok := t.tdev.(tun.GRODevice)
	if !ok {
		return
	}
	if knobs.DisableTUNUDPGRO.Load() {
		groDev.DisableUDPGRO()
	}
	if knobs.DisableTUNTCPGRO.Load() {
		groDev.DisableTCPGRO()
	}
}

func probeTCPGRO(dev tun.GRODevice) error {
	ipPort := netip.MustParseAddrPort(tsaddr.TailscaleServiceIPString + ":0")
	fingerprint := []byte("tailscale-probe-tun-gro")
	segmentSize := len(fingerprint)
	iphLen := 20
	tcphLen := 20
	totalLen := iphLen + tcphLen + segmentSize
	ipAs4 := ipPort.Addr().As4()
	bufs := make([][]byte, 2)
	for i := range bufs {
		bufs[i] = make([]byte, PacketStartOffset+totalLen, PacketStartOffset+(totalLen*2))
		ipv4H := header.IPv4(bufs[i][PacketStartOffset:])
		ipv4H.Encode(&header.IPv4Fields{
			SrcAddr:  tcpip.AddrFromSlice(ipAs4[:]),
			DstAddr:  tcpip.AddrFromSlice(ipAs4[:]),
			Protocol: unix.IPPROTO_TCP,
			// Use a zero value TTL as best effort means to reduce chance of
			// probe packet leaking further than it needs to.
			TTL:         0,
			TotalLength: uint16(totalLen),
		})
		tcpH := header.TCP(bufs[i][PacketStartOffset+iphLen:])
		tcpH.Encode(&header.TCPFields{
			SrcPort:    ipPort.Port(),
			DstPort:    ipPort.Port(),
			SeqNum:     1 + uint32(i*segmentSize),
			AckNum:     1,
			DataOffset: 20,
			Flags:      header.TCPFlagAck,
			WindowSize: 3000,
		})
		copy(bufs[i][PacketStartOffset+iphLen+tcphLen:], fingerprint)
		ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
		pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ipv4H.SourceAddress(), ipv4H.DestinationAddress(), uint16(tcphLen+segmentSize))
		pseudoCsum = checksum.Checksum(bufs[i][PacketStartOffset+iphLen+tcphLen:], pseudoCsum)
		tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))
	}
	_, err := dev.Write(bufs, PacketStartOffset)
	return err
}
