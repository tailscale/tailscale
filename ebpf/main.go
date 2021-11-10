package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.zx2c4.com/wireguard/tun"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -Iinclude" bpf bpf.c

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}

const (
	divertInterface    = "hack0"
	tailscaleInterface = "tailscale0"
)

func run() error {
	dev, err := tun.CreateTUN(divertInterface, 1280)
	if err != nil {
		return fmt.Errorf("creating tun: %v", err)
	}
	defer dev.Close()

	divertIdx, err := ifIndex(divertInterface)
	if err != nil {
		return fmt.Errorf("getting index of divert interface: %v", err)
	}
	tailscaleIdx, err := ifIndex(tailscaleInterface)
	if err != nil {
		return fmt.Errorf("getting index of tailscale interface: %v", err)
	}

	// Prevent IPv6 link-local spam
	if err := exec.Command("ip", "link", "set", divertInterface, "addrgenmode", "none").Run(); err != nil {
		return fmt.Errorf("bringing up iface: %v", err)
	}
	if err := exec.Command("ip", "link", "set", divertInterface, "up").Run(); err != nil {
		return fmt.Errorf("bringing up iface: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading tailscale egress program: %v", err)
	}
	err = spec.RewriteConstants(map[string]interface{}{
		"ifidx_divert":    divertIdx,
		"ifidx_tailscale": tailscaleIdx,
	})
	if err != nil {
		return fmt.Errorf("setting interface ID: %v", err)
	}
	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("loading tailscale egress program: %v", err)
	}
	defer objs.Close()

	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("opening rtnetlink socket: %v", err)
	}
	defer tcnl.Close()

	qdisc := tc.Object{
		tc.Msg{
			Ifindex: tailscaleIdx,
			Handle:  core.BuildHandle(tc.HandleIngress, 0),
			Parent:  tc.HandleIngress,
		},
		tc.Attribute{
			Kind: "clsact",
		},
	}
	if err := tcnl.Qdisc().Replace(&qdisc); err != nil {
		return fmt.Errorf("adding/replacing clsact qdisc on tailscale interface: %v", err)
	}
	qdisc.Msg.Ifindex = divertIdx
	if err := tcnl.Qdisc().Replace(&qdisc); err != nil {
		return fmt.Errorf("adding/replacing clsact qdisc on divert interface: %v", err)
	}

	fd := uint32(objs.EgressTailscale.FD())
	flags := uint32(1) // TCA_BPF_FLAG_ACT_DIRECT
	handleEgress := uint32(0xFFFFFFF3)
	name := "fucksake"
	filter := &tc.Object{
		tc.Msg{
			Ifindex: tailscaleIdx,
			Parent:  handleEgress,
			Handle:  1,
			Info:    0x0300, // ETH_P_ALL, byteswapped into the lower 16 bits of info. Yeah, really.
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Name:  &name,
				Flags: &flags,
			},
		},
	}
	fmt.Println(fd)
	if err := tcnl.Filter().Add(filter); err != nil {
		return fmt.Errorf("adding/replacing tailscale egress filter: %v", err)
	}

	if err := dumpPackets(dev); err != nil {
		return fmt.Errorf("reading packets: %v", err)
	}
	return nil
}

func ifIndex(name string) (uint32, error) {
	intf, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return uint32(intf.Index), nil
}

func dumpPackets(dev tun.Device) error {
	for {
		var b [1284]byte
		n, err := dev.Read(b[:], 4)
		if err != nil {
			return fmt.Errorf("reading from tun: %v", err)
		}

		bs := b[4 : 4+n]

		fmt.Printf("received packet of %d bytes\n", len(bs))
		hexdump(bs)
	}
}

func hexdump(bs []byte) {
	for i := range bs {
		switch {
		case i == 0:
		case i%16 == 0:
			fmt.Println("")
		case i%8 == 0:
			fmt.Printf("  ")
		}
		fmt.Printf("%02x ", bs[i])
	}
	fmt.Printf("\n\n")
}
