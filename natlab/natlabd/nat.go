package main

import (
	"net/netip"
	"time"
)

// NATTable is what a NAT implementation is expected to do.
//
// This project tests Tailscale as it faces various combinations various NAT
// implementations (e.g. Linux easy style NAT vs FreeBSD hard/endpoint dependent
// NAT vs Cloud 1:1 NAT, etc)
//
// Implementations of NATTable need not handle concurrency; the natlab serializes
// all calls into a NATTable.
//
// The provided `at` value will typically be time.Now, except for tests.
// Implementations should not use real time and should only compare
// previously provided time values.
type NATTable interface {
	// PickOutgoingSrc returns the source address to use for an outgoing packet.
	//
	// The result should either be invalid (to drop the packet) or a WAN (not
	// private) IP address.
	//
	// Typically, the src is a LAN source IP address, but it might also be a WAN
	// IP address if the packet is being forwarded for a source machine that has
	// a public IP address.
	PickOutgoingSrc(src, dst netip.AddrPort, at time.Time) (wanSrc netip.AddrPort)

	// PickIncomingDst returns the destination address to use for an incoming
	// packet. The incoming src address is always a public WAN IP.
	//
	// The result should either be invalid (to drop the packet) or the IP
	// address of a machine on the local network address, usually a private
	// LAN IP.
	PickIncomingDst(src, dst netip.AddrPort, at time.Time) (lanDst netip.AddrPort)
}

// oneToOneNAT is a 1:1 NAT, like a typical EC2 VM.
type oneToOneNAT struct {
	lanIP netip.Addr
	wanIP netip.Addr
}

func (n *oneToOneNAT) PickOutgoingSrc(src, dst netip.AddrPort, at time.Time) (wanSrc netip.AddrPort) {
	return netip.AddrPortFrom(n.wanIP, src.Port())
}

func (n *oneToOneNAT) PickIncomingDst(src, dst netip.AddrPort, at time.Time) (lanDst netip.AddrPort) {
	return netip.AddrPortFrom(n.lanIP, dst.Port())
}
