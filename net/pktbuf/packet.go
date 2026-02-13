package pktbuf

import (
	"encoding/binary"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// A Segment is a chunk of bytes extracted from a Packet.
//
// The bytes are not accessible directly through the Segment. The only
// valid operation on Segments is to reattach them to a Packet.
type Segment struct {
	arena *Arena
	buf   chunkBuffer
}

// A Packet is a bunch of bytes with attached metadata.
type Packet[Meta any] struct {
	arena *Arena
	buf   chunkBuffer
	Meta  Meta
}

// NewPacket allocates a new packet from the given arena, containing
// sz zero bytes and with the given metadata attached.
func NewPacket[Meta any](arena *Arena, sz int, meta Meta) *Packet[Meta] {
	ret := &Packet[Meta]{
		arena: arena,
		Meta:  meta,
	}
	ret.Grow(sz)
	return ret
}

// Extract removes the slice [off:off+sz] from the packet, and returns
// it as a Segment.
func (p *Packet[Meta]) Extract(off, sz int) Segment {
	return Segment{
		arena: p.arena,
		buf:   p.buf.extract(off, sz),
	}
}

// Append appends the given Segments to the end of the packet.
func (p *Packet[Meta]) Append(segs ...Segment) {
	for _, seg := range segs {
		if seg.arena != p.arena {
			panic("cannot append segment from different arena")
		}
		p.buf.append(seg.buf.allChunks()...)
	}
}

// AppendBytes appends bs to the end of the packet.
//
// bs is copied into a fresh allocation from the packet's Arena.
func (p *Packet[Meta]) AppendBytes(bs []byte) {
	b := p.arena.Get(len(bs))
	copy(b, bs)
	p.buf.append(b)
}

// Prepend prepends the given Segments to the start of the packet.
func (p *Packet[Meta]) Prepend(segs ...Segment) {
	for _, seg := range segs {
		if seg.arena != p.arena {
			panic("cannot prepend segment from different arena")
		}
		p.buf.prepend(seg.buf.allChunks()...)
	}
}

// PrependBytes prepends the given bytes to the start of the packet.
//
// bs is copied into a fresh allocation from the packet's Arena.
func (p *Packet[Meta]) PrependBytes(bs []byte) {
	b := p.arena.Get(len(bs))
	copy(b, bs)
	p.buf.prepend(b)
}

// Insert inserts seg into the packet at the given offset.
func (p *Packet[Meta]) Insert(off int, seg Segment) {
	p.buf.splice(&seg.buf, off)
}

// Grow adds sz zero bytes to the end of the packet.
func (p *Packet[Meta]) Grow(sz int) {
	if sz == 0 {
		return
	}
	p.buf.append(p.arena.Get(sz))
}

// GrowFront adds sz zero bytes to the start of the packet.
func (p *Packet[Meta]) GrowFront(sz int) {
	if sz == 0 {
		return
	}
	p.buf.prepend(p.arena.Get(sz))
}

// WriteAt writes bs to the given offset in the packet.
//
// Panics if the range [off:off+len(bs)] is out of bounds.
func (p *Packet[Meta]) WriteAt(bs []byte, off int64) {
	p.buf.writeAt(bs, int(off))
}

// ReadAt reads len(bs) bytes from the given offset in the packet.
//
// Panics if the range [off:off+len(bs)] is out of bounds.
func (p *Packet[Meta]) ReadAt(bs []byte, off int64) {
	p.buf.readAt(bs, int(off))
}

// Uint8 returns the value of the byte at off in the packet.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) Uint8(off int64) byte {
	var bs [1]byte
	p.ReadAt(bs[:], off)
	return bs[0]
}

// Uint16BE returns the big-endian 16-bit value at off in the packet.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) Uint16BE(off int64) uint16 {
	var bs [2]byte
	p.ReadAt(bs[:], off)
	return binary.BigEndian.Uint16(bs[:])
}

// Uint16LE returns the little-endian 16-bit value at off in the
// packet.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) Uint16LE(off int64) uint16 {
	var bs [2]byte
	p.ReadAt(bs[:], off)
	return binary.LittleEndian.Uint16(bs[:])
}

// Uint32BE returns the big-endian 32-bit value at off in the
// packet.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) Uint32BE(off int64) uint32 {
	var bs [4]byte
	p.ReadAt(bs[:], off)
	return binary.BigEndian.Uint32(bs[:])
}

// Uint32LE returns the little-endian 32-bit value at off in the
// packet.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) Uint32LE(off int64) uint32 {
	var bs [4]byte
	p.ReadAt(bs[:], off)
	return binary.LittleEndian.Uint32(bs[:])
}

// Uint64BE returns the big-endian 64-bit value at off in the
// packet.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) Uint64BE(off int64) uint64 {
	var bs [8]byte
	p.ReadAt(bs[:], off)
	return binary.BigEndian.Uint64(bs[:])
}

// Uint64LE returns the little-endian 64-bit value at off in the
// packet.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) Uint64LE(off int64) uint64 {
	var bs [8]byte
	p.ReadAt(bs[:], off)
	return binary.LittleEndian.Uint64(bs[:])
}

// PutUint8 writes v at the given offset.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) PutUint8(v byte, off int64) {
	var bs [1]byte
	bs[0] = v
	p.buf.writeAt(bs[:], int(off))
}

// PutUint16BE writes v in big-endian order at the given offset.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) PutUint16BE(v uint16, off int64) {
	var bs [2]byte
	binary.BigEndian.PutUint16(bs[:], v)
	p.WriteAt(bs[:], off)
}

// PutUint16LE writes v in little-endian order at the given offset.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) PutUint16LE(v uint16, off int64) {
	var bs [2]byte
	binary.LittleEndian.PutUint16(bs[:], v)
	p.WriteAt(bs[:], off)
}

// PutUint32BE writes v in big-endian order at the given offset.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) PutUint32BE(v uint32, off int64) {
	var bs [4]byte
	binary.BigEndian.PutUint32(bs[:], v)
	p.WriteAt(bs[:], off)
}

// PutUint32LE writes v in little-endian order at the given offset.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) PutUint32LE(v uint32, off int64) {
	var bs [4]byte
	binary.LittleEndian.PutUint32(bs[:], v)
	p.WriteAt(bs[:], off)
}

// PutUint64BE writes v in big-endian order at the given offset.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) PutUint64BE(v uint64, off int64) {
	var bs [8]byte
	binary.BigEndian.PutUint64(bs[:], v)
	p.WriteAt(bs[:], off)
}

// PutUint64LE writes v in little-endian order at the given offset.
//
// Panics if off is out of bounds.
func (p *Packet[Meta]) PutUint64LE(v uint64, off int64) {
	var bs [8]byte
	binary.LittleEndian.PutUint64(bs[:], v)
	p.WriteAt(bs[:], off)
}

// Message4 constructs an ipv4.Message from the packet.
//
// The ipv4.Message is only valid until the next mutation of the
// packet.
func (p *Packet[Meta]) Message4() ipv4.Message {
	return ipv4.Message{
		Buffers: p.buf.allChunks(),
	}
}

// Message6 constructs an ipv6.Message from the packet.
//
// The ipv6.Message is only valid until the next mutation of the
// packet.
func (p *Packet[Meta]) Message6() ipv6.Message {
	return ipv6.Message{
		Buffers: p.buf.allChunks(),
	}
}
