// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package xdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type config -type endpoint bpf xdp.c -- -I ../../../derp/xdp/headers

func NewFIB(config *FIBConfig, opts ...FIBOption) (FIB, error) {
	o := &fibOptions{}
	for _, opt := range opts {
		opt.apply(o)
	}
	err := config.validate()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	objs := new(bpfObjects)
	err = loadBpfObjects(objs, nil)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			err = fmt.Errorf("verifier error: %+v", ve)
		}
		return nil, fmt.Errorf("error loading XDP program: %w", err)
	}
	f := &linuxFIB{
		objs:    objs,
		dstPort: config.DstPort,
	}
	var key uint32
	xdpConfig := &bpfConfig{
		DstPort: config.DstPort,
	}
	err = objs.ConfigMap.Put(key, xdpConfig)
	if err != nil {
		return nil, fmt.Errorf("error loading config in eBPF map: %w", err)
	}
	if o.noAttach {
		return f, nil
	}
	iface, err := net.InterfaceByName(config.DeviceName)
	if err != nil {
		return nil, fmt.Errorf("error finding device: %w", err)
	}
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
		Flags:     link.XDPAttachFlags(config.AttachFlags),
	})
	if err != nil {
		return nil, fmt.Errorf("error attaching XDP program to dev: %w", err)
	}
	f.link = link
	return f, nil
}

type linuxFIB struct {
	objs    *bpfObjects
	dstPort uint16
	link    link.Link
}

func (l *linuxFIB) Delete(vni uint32) error {
	return l.objs.EndpointMap.Delete(&vni)
}

func (l *linuxFIB) Upsert(vni uint32, participants [2]netip.AddrPort) error {
	endpoint := bpfEndpoint{}
	for i, participant := range participants {
		as16 := participant.Addr().As16()
		for j := 0; j < 4; j++ {
			endpoint.ParticipantAddrs[i][j] = binary.NativeEndian.Uint32(as16[j*4:])
		}
		endpoint.ParticipantPorts[i] = participant.Port()
		if participant.Addr().Is6() {
			endpoint.ParticipantIsIpv6[i] = 1
		}
	}
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	vals := make([]bpfEndpoint, numCPU)
	for i := range vals {
		vals[i] = endpoint
	}
	return l.objs.EndpointMap.Put(&vni, vals)
}

func (l *linuxFIB) Close() error { return nil }
