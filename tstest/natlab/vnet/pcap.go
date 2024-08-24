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

// pcapWriter is a pcapgo.NgWriter that writes to a file.
// It is safe for concurrent use. The nil value is a no-op.
type pcapWriter struct {
	f *os.File

	mu sync.Mutex
	w  *pcapgo.NgWriter
}

func do(fs ...func() error) error {
	for _, f := range fs {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}

func (p *pcapWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.w == nil {
		return io.ErrClosedPipe
	}
	return do(
		func() error { return p.w.WritePacket(ci, data) },
		p.w.Flush,
		p.f.Sync,
	)
}

func (p *pcapWriter) AddInterface(i pcapgo.NgInterface) (int, error) {
	if p == nil {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.w.AddInterface(i)
}

func (p *pcapWriter) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.w != nil {
		p.w.Flush()
		p.w = nil
	}
	return p.f.Close()
}
