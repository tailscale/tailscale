// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// Package xlatbpf is net/via64/xlat's translator: two BPF programs on the netkit pair.
package xlatbpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type config bpf xlat.c -- -I ../../../derp/xdp/headers -I /usr/include/x86_64-linux-gnu -I /usr/include/aarch64-linux-gnu

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"tailscale.com/net/via64/xlat"
)

type backend struct {
	objs  bpfObjects
	links []link.Link
}

// New loads the translator programs. They are attached by Install.
func New() (xlat.Backend, error) {
	b := &backend{}
	if err := loadBpfObjects(&b.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("loading via64 BPF objects: %+v", ve)
		}
		return nil, fmt.Errorf("loading via64 BPF objects: %w", err)
	}
	return b, nil
}

func (b *backend) Install(p xlat.Pair, x xlat.Xlat) error {
	if err := b.setConfig(x); err != nil {
		return err
	}
	// Both attach through the primary; netkit runs each on its device's transmit.
	primary, err := link.AttachNetkit(link.NetkitOptions{Program: b.objs.Xlat6to4, Interface: p.PrimaryIndex, Attach: ebpf.AttachNetkitPrimary})
	if err != nil {
		return fmt.Errorf("attaching xlat6to4 to %s: %w", xlat.PrimaryName, err)
	}
	peer, err := link.AttachNetkit(link.NetkitOptions{Program: b.objs.Xlat4to6, Interface: p.PrimaryIndex, Attach: ebpf.AttachNetkitPeer})
	if err != nil {
		primary.Close()
		return fmt.Errorf("attaching xlat4to6 to %s: %w", xlat.PeerName, err)
	}
	b.links = []link.Link{primary, peer}
	return nil
}

func (b *backend) setConfig(x xlat.Xlat) error {
	c := xlat.Canonical.Addr().As16()
	x4 := x.X4.As4()
	cfg := bpfConfig{
		// Network byte order whatever the host's endianness.
		Prefix: [3]uint32{binary.NativeEndian.Uint32(c[0:4]), binary.NativeEndian.Uint32(c[4:8]), binary.NativeEndian.Uint32(c[8:12])},
		X4:     binary.NativeEndian.Uint32(x4[:]),
	}
	if err := b.objs.ConfigMap.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("config_map: %w", err)
	}
	return nil
}

func (b *backend) Close() error {
	var errs []error
	for _, l := range b.links {
		errs = append(errs, l.Close())
	}
	b.links = nil
	errs = append(errs, b.objs.Close())
	return errors.Join(errs...)
}
