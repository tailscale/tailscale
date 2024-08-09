package vnet

import (
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type pcapWriter struct {
	f *os.File

	mu sync.Mutex
	w  *pcapgo.Writer
}

func (p *pcapWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.w.WritePacket(ci, data)
}

func (p *pcapWriter) Close() error {
	return p.f.Close()
}
