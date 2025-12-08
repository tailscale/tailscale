package xdp

import "net/netip"

// XDPAttachFlags represents how XDP program will be attached to interface. This
// is a mirror of cilium/ebpf/link.AttachFlags, without pulling it in for
// non-Linux.
type XDPAttachFlags uint32

const (
	// XDPDriverFallbackGenericMode attempts XDPDriverMode, and falls back to
	// XDPGenericMode if the driver does not support XDP.
	XDPDriverFallbackGenericMode = 0
)

const (
	// XDPGenericMode (SKB) links XDP BPF program for drivers which do
	// not yet support native XDP.
	XDPGenericMode XDPAttachFlags = 1 << (iota + 1)
	// XDPDriverMode links XDP BPF program into the driver’s receive path.
	XDPDriverMode
	// XDPOffloadMode offloads the entire XDP BPF program into hardware.
	XDPOffloadMode
)

type FIBConfig struct {
	DeviceName string
	// TODO: DstPort is singular, but udp4 and udp6 can be independent ports if
	//  the user supplied a zero port value.
	DstPort     uint16
	AttachFlags XDPAttachFlags
}

func (f FIBConfig) validate() error { return nil }

type FIBOption interface {
	apply(*fibOptions)
}

type fibOptions struct {
	noAttach bool
}

type FIB interface {
	Delete(vni uint32) error
	Upsert(vni uint32, participants [2]netip.AddrPort) error
	Close() error
}
