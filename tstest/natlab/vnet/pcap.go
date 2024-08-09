// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"io"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type pcapWriter struct {
	f *os.File

	mu sync.Mutex
	w  *pcapgo.NgWriter
}

func (p *pcapWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.w == nil {
		return io.ErrClosedPipe
	}
	return p.w.WritePacket(ci, data)
}

func (p *pcapWriter) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.w != nil {
		p.w.Flush()
		p.w = nil
	}
	return p.f.Close()
}
