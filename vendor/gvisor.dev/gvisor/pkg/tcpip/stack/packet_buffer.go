// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	tcpipbuffer "gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type headerType int

const (
	virtioNetHeader headerType = iota
	linkHeader
	networkHeader
	transportHeader
	numHeaderType
)

var pkPool = sync.Pool{
	New: func() interface{} {
		return &PacketBuffer{}
	},
}

// PacketBufferOptions specifies options for PacketBuffer creation.
type PacketBufferOptions struct {
	// ReserveHeaderBytes is the number of bytes to reserve for headers. Total
	// number of bytes pushed onto the headers must not exceed this value.
	ReserveHeaderBytes int

	// Data is the initial unparsed data for the new packet. If set, it will be
	// owned by the new packet.
	Data tcpipbuffer.VectorisedView

	// IsForwardedPacket identifies that the PacketBuffer being created is for a
	// forwarded packet.
	IsForwardedPacket bool
}

// A PacketBuffer contains all the data of a network packet.
//
// As a PacketBuffer traverses up the stack, it may be necessary to pass it to
// multiple endpoints.
//
// The whole packet is expected to be a series of bytes in the following order:
// LinkHeader, NetworkHeader, TransportHeader, and Data. Any of them can be
// empty. Use of PacketBuffer in any other order is unsupported.
//
// PacketBuffer must be created with NewPacketBuffer.
//
// Internal structure: A PacketBuffer holds a pointer to buffer.Buffer, which
// exposes a logically-contiguous byte storage. The underlying storage structure
// is abstracted out, and should not be a concern here for most of the time.
//
// |- reserved ->|
//               |--->| consumed (incoming)
// 0             V    V
// +--------+----+----+--------------------+
// |        |    |    | current data ...   | (buf)
// +--------+----+----+--------------------+
//          ^    |
//          |<---| pushed (outgoing)
//
// When a PacketBuffer is created, a `reserved` header region can be specified,
// which stack pushes headers in this region for an outgoing packet. There could
// be no such region for an incoming packet, and `reserved` is 0. The value of
// `reserved` never changes in the entire lifetime of the packet.
//
// Outgoing Packet: When a header is pushed, `pushed` gets incremented by the
// pushed length, and the current value is stored for each header. PacketBuffer
// substracts this value from `reserved` to compute the starting offset of each
// header in `buf`.
//
// Incoming Packet: When a header is consumed (a.k.a. parsed), the current
// `consumed` value is stored for each header, and it gets incremented by the
// consumed length. PacketBuffer adds this value to `reserved` to compute the
// starting offset of each header in `buf`.
//
// +stateify savable
type PacketBuffer struct {
	_ sync.NoCopy

	packetBufferRefs

	// PacketBufferEntry is used to build an intrusive list of
	// PacketBuffers.
	PacketBufferEntry

	// buf is the underlying buffer for the packet. See struct level docs for
	// details.
	buf      buffer.Buffer
	reserved int
	pushed   int
	consumed int

	// headers stores metadata about each header.
	headers [numHeaderType]headerInfo

	// NetworkProtocolNumber is only valid when NetworkHeader().View().IsEmpty()
	// returns false.
	// TODO(gvisor.dev/issue/3574): Remove the separately passed protocol
	// numbers in registration APIs that take a PacketBuffer.
	NetworkProtocolNumber tcpip.NetworkProtocolNumber

	// TransportProtocol is only valid if it is non zero.
	// TODO(gvisor.dev/issue/3810): This and the network protocol number should
	// be moved into the headerinfo. This should resolve the validity issue.
	TransportProtocolNumber tcpip.TransportProtocolNumber

	// Hash is the transport layer hash of this packet. A value of zero
	// indicates no valid hash has been set.
	Hash uint32

	// Owner is implemented by task to get the uid and gid.
	// Only set for locally generated packets.
	Owner tcpip.PacketOwner

	// The following fields are only set by the qdisc layer when the packet
	// is added to a queue.
	EgressRoute RouteInfo
	GSOOptions  GSO

	// snatDone indicates if the packet's source has been manipulated as per
	// iptables NAT table.
	snatDone bool

	// dnatDone indicates if the packet's destination has been manipulated as per
	// iptables NAT table.
	dnatDone bool

	// PktType indicates the SockAddrLink.PacketType of the packet as defined in
	// https://www.man7.org/linux/man-pages/man7/packet.7.html.
	PktType tcpip.PacketType

	// NICID is the ID of the last interface the network packet was handled at.
	NICID tcpip.NICID

	// RXTransportChecksumValidated indicates that transport checksum verification
	// may be safely skipped.
	RXTransportChecksumValidated bool

	// NetworkPacketInfo holds an incoming packet's network-layer information.
	NetworkPacketInfo NetworkPacketInfo

	tuple *tuple

	preserveObject bool
}

// NewPacketBuffer creates a new PacketBuffer with opts.
func NewPacketBuffer(opts PacketBufferOptions) *PacketBuffer {
	pk := pkPool.Get().(*PacketBuffer)
	pk.reset()
	if opts.ReserveHeaderBytes != 0 {
		pk.buf.AppendOwned(make([]byte, opts.ReserveHeaderBytes))
		pk.reserved = opts.ReserveHeaderBytes
	}
	for _, v := range opts.Data.Views() {
		pk.buf.AppendOwned(v)
	}
	if opts.IsForwardedPacket {
		pk.NetworkPacketInfo.IsForwardedPacket = opts.IsForwardedPacket
	}
	pk.InitRefs()
	return pk
}

// PreserveObject marks this PacketBuffer so it is not recycled by internal
// pooling.
func (pk *PacketBuffer) PreserveObject() {
	pk.preserveObject = true
}

// DecRef decrements the PacketBuffer's refcount. If the refcount is
// decremented to zero, the PacketBuffer is returned to the PacketBuffer
// pool.
func (pk *PacketBuffer) DecRef() {
	pk.packetBufferRefs.DecRef(func() {
		if pk.packetBufferRefs.refCount == 0 && !pk.preserveObject {
			pkPool.Put(pk)
		}
	})
}

func (pk *PacketBuffer) reset() {
	*pk = PacketBuffer{}
}

// ReservedHeaderBytes returns the number of bytes initially reserved for
// headers.
func (pk *PacketBuffer) ReservedHeaderBytes() int {
	return pk.reserved
}

// AvailableHeaderBytes returns the number of bytes currently available for
// headers. This is relevant to PacketHeader.Push method only.
func (pk *PacketBuffer) AvailableHeaderBytes() int {
	return pk.reserved - pk.pushed
}

// VirtioNetHeader returns the handle to virtio-layer header.
func (pk *PacketBuffer) VirtioNetHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: virtioNetHeader,
	}
}

// LinkHeader returns the handle to link-layer header.
func (pk *PacketBuffer) LinkHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: linkHeader,
	}
}

// NetworkHeader returns the handle to network-layer header.
func (pk *PacketBuffer) NetworkHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: networkHeader,
	}
}

// TransportHeader returns the handle to transport-layer header.
func (pk *PacketBuffer) TransportHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: transportHeader,
	}
}

// HeaderSize returns the total size of all headers in bytes.
func (pk *PacketBuffer) HeaderSize() int {
	return pk.pushed + pk.consumed
}

// Size returns the size of packet in bytes.
func (pk *PacketBuffer) Size() int {
	return int(pk.buf.Size()) - pk.headerOffset()
}

// MemSize returns the estimation size of the pk in memory, including backing
// buffer data.
func (pk *PacketBuffer) MemSize() int {
	return int(pk.buf.Size()) + packetBufferStructSize
}

// Data returns the handle to data portion of pk.
func (pk *PacketBuffer) Data() PacketData {
	return PacketData{pk: pk}
}

// Views returns the underlying storage of the whole packet.
func (pk *PacketBuffer) Views() []tcpipbuffer.View {
	var views []tcpipbuffer.View
	offset := pk.headerOffset()
	pk.buf.SubApply(offset, int(pk.buf.Size())-offset, func(v []byte) {
		views = append(views, v)
	})
	return views
}

func (pk *PacketBuffer) headerOffset() int {
	return pk.reserved - pk.pushed
}

func (pk *PacketBuffer) headerOffsetOf(typ headerType) int {
	return pk.reserved + pk.headers[typ].offset
}

func (pk *PacketBuffer) dataOffset() int {
	return pk.reserved + pk.consumed
}

func (pk *PacketBuffer) push(typ headerType, size int) tcpipbuffer.View {
	h := &pk.headers[typ]
	if h.length > 0 {
		panic(fmt.Sprintf("push(%s, %d) called after previous push", typ, size))
	}
	if pk.pushed+size > pk.reserved {
		panic(fmt.Sprintf("push(%s, %d) overflows; pushed=%d reserved=%d", typ, size, pk.pushed, pk.reserved))
	}
	pk.pushed += size
	h.offset = -pk.pushed
	h.length = size
	return pk.headerView(typ)
}

func (pk *PacketBuffer) consume(typ headerType, size int) (v tcpipbuffer.View, consumed bool) {
	h := &pk.headers[typ]
	if h.length > 0 {
		panic(fmt.Sprintf("consume must not be called twice: type %s", typ))
	}
	if pk.reserved+pk.consumed+size > int(pk.buf.Size()) {
		return nil, false
	}
	h.offset = pk.consumed
	h.length = size
	pk.consumed += size
	return pk.headerView(typ), true
}

func (pk *PacketBuffer) headerView(typ headerType) tcpipbuffer.View {
	h := &pk.headers[typ]
	if h.length == 0 {
		return nil
	}
	v, ok := pk.buf.PullUp(pk.headerOffsetOf(typ), h.length)
	if !ok {
		panic("PullUp failed")
	}
	return v
}

// Clone makes a semi-deep copy of pk. The underlying packet payload is
// shared. Hence, no modifications is done to underlying packet payload.
func (pk *PacketBuffer) Clone() *PacketBuffer {
	newPk := pkPool.Get().(*PacketBuffer)
	newPk.PacketBufferEntry = pk.PacketBufferEntry
	newPk.buf = pk.buf.Clone()
	newPk.reserved = pk.reserved
	newPk.pushed = pk.pushed
	newPk.consumed = pk.consumed
	newPk.headers = pk.headers
	newPk.Hash = pk.Hash
	newPk.Owner = pk.Owner
	newPk.GSOOptions = pk.GSOOptions
	newPk.NetworkProtocolNumber = pk.NetworkProtocolNumber
	newPk.dnatDone = pk.dnatDone
	newPk.snatDone = pk.snatDone
	newPk.TransportProtocolNumber = pk.TransportProtocolNumber
	newPk.PktType = pk.PktType
	newPk.NICID = pk.NICID
	newPk.RXTransportChecksumValidated = pk.RXTransportChecksumValidated
	newPk.NetworkPacketInfo = pk.NetworkPacketInfo
	newPk.tuple = pk.tuple
	newPk.InitRefs()
	return newPk
}

// Network returns the network header as a header.Network.
//
// Network should only be called when NetworkHeader has been set.
func (pk *PacketBuffer) Network() header.Network {
	switch netProto := pk.NetworkProtocolNumber; netProto {
	case header.IPv4ProtocolNumber:
		return header.IPv4(pk.NetworkHeader().View())
	case header.IPv6ProtocolNumber:
		return header.IPv6(pk.NetworkHeader().View())
	default:
		panic(fmt.Sprintf("unknown network protocol number %d", netProto))
	}
}

// CloneToInbound makes a semi-deep copy of the packet buffer (similar to
// Clone) to be used as an inbound packet.
//
// See PacketBuffer.Data for details about how a packet buffer holds an inbound
// packet.
func (pk *PacketBuffer) CloneToInbound() *PacketBuffer {
	newPk := pkPool.Get().(*PacketBuffer)
	newPk.reset()
	newPk.buf = pk.buf.Clone()
	newPk.InitRefs()
	// Treat unfilled header portion as reserved.
	newPk.reserved = pk.AvailableHeaderBytes()
	newPk.tuple = pk.tuple
	return newPk
}

// DeepCopyForForwarding creates a deep copy of the packet buffer for
// forwarding.
//
// The returned packet buffer will have the network and transport headers
// set if the original packet buffer did.
func (pk *PacketBuffer) DeepCopyForForwarding(reservedHeaderBytes int) *PacketBuffer {
	newPk := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: reservedHeaderBytes,
		Data:               PayloadSince(pk.NetworkHeader()).ToVectorisedView(),
		IsForwardedPacket:  true,
	})

	{
		consumeBytes := pk.NetworkHeader().View().Size()
		if _, consumed := newPk.NetworkHeader().Consume(consumeBytes); !consumed {
			panic(fmt.Sprintf("expected to consume network header %d bytes from new packet", consumeBytes))
		}
		newPk.NetworkProtocolNumber = pk.NetworkProtocolNumber
	}

	{
		consumeBytes := pk.TransportHeader().View().Size()
		if _, consumed := newPk.TransportHeader().Consume(consumeBytes); !consumed {
			panic(fmt.Sprintf("expected to consume transport header %d bytes from new packet", consumeBytes))
		}
		newPk.TransportProtocolNumber = pk.TransportProtocolNumber
	}

	newPk.tuple = pk.tuple

	return newPk
}

// IncRef increases the reference count on each PacketBuffer
// stored in the PacketBufferList.
func (pk *PacketBufferList) IncRef() {
	for pb := pk.Front(); pb != nil; pb = pb.Next() {
		pb.IncRef()
	}
}

// DecRef decreases the reference count on each PacketBuffer
// stored in the PacketBufferList.
func (pk *PacketBufferList) DecRef() {
	// Using a while-loop here (instead of for-loop) because DecRef() can cause
	// the pb to be recycled. If it is recycled during execution of this loop,
	// there is a possibility of a data race during a call to pb.Next().
	pb := pk.Front()
	for pb != nil {
		next := pb.Next()
		pb.DecRef()
		pb = next
	}
}

// headerInfo stores metadata about a header in a packet.
//
// +stateify savable
type headerInfo struct {
	// offset is the offset of the header in pk.buf relative to
	// pk.buf[pk.reserved]. See the PacketBuffer struct for details.
	offset int

	// length is the length of this header.
	length int
}

// PacketHeader is a handle object to a header in the underlying packet.
type PacketHeader struct {
	pk  *PacketBuffer
	typ headerType
}

// View returns the underlying storage of h.
func (h PacketHeader) View() tcpipbuffer.View {
	return h.pk.headerView(h.typ)
}

// Push pushes size bytes in the front of its residing packet, and returns the
// backing storage. Callers may only call one of Push or Consume once on each
// header in the lifetime of the underlying packet.
func (h PacketHeader) Push(size int) tcpipbuffer.View {
	return h.pk.push(h.typ, size)
}

// Consume moves the first size bytes of the unparsed data portion in the packet
// to h, and returns the backing storage. In the case of data is shorter than
// size, consumed will be false, and the state of h will not be affected.
// Callers may only call one of Push or Consume once on each header in the
// lifetime of the underlying packet.
func (h PacketHeader) Consume(size int) (v tcpipbuffer.View, consumed bool) {
	return h.pk.consume(h.typ, size)
}

// PacketData represents the data portion of a PacketBuffer.
//
// +stateify savable
type PacketData struct {
	pk *PacketBuffer
}

// PullUp returns a contiguous view of size bytes from the beginning of d.
// Callers should not write to or keep the view for later use.
func (d PacketData) PullUp(size int) (tcpipbuffer.View, bool) {
	return d.pk.buf.PullUp(d.pk.dataOffset(), size)
}

// Consume is the same as PullUp except that is additionally consumes the
// returned bytes. Subsequent PullUp or Consume will not return these bytes.
func (d PacketData) Consume(size int) (tcpipbuffer.View, bool) {
	v, ok := d.PullUp(size)
	if ok {
		d.pk.consumed += size
	}
	return v, ok
}

// ReadTo reads bytes from d to dst. It also removes these bytes from d
// unless peek is true.
func (d PacketData) ReadTo(dst io.Writer, peek bool) (int, error) {
	var err error
	done := 0
	for _, v := range d.Views() {
		var n int
		n, err = dst.Write(v)
		done += n
		if err != nil {
			break
		}
		if n != len(v) {
			panic(fmt.Sprintf("io.Writer.Write succeeded with incomplete write: %d != %d", n, len(v)))
		}
	}
	if !peek {
		d.pk.buf.TrimFront(int64(done))
	}
	return done, err
}

// CapLength reduces d to at most length bytes.
func (d PacketData) CapLength(length int) {
	if length < 0 {
		panic("length < 0")
	}
	if currLength := d.Size(); currLength > length {
		trim := currLength - length
		d.pk.buf.Remove(int(d.pk.buf.Size())-trim, trim)
	}
}

// Views returns the underlying storage of d in a slice of Views. Caller should
// not modify the returned slice.
func (d PacketData) Views() []tcpipbuffer.View {
	var views []tcpipbuffer.View
	offset := d.pk.dataOffset()
	d.pk.buf.SubApply(offset, int(d.pk.buf.Size())-offset, func(v []byte) {
		views = append(views, v)
	})
	return views
}

// AppendView appends v into d, taking the ownership of v.
func (d PacketData) AppendView(v tcpipbuffer.View) {
	d.pk.buf.AppendOwned(v)
}

// MergeFragment appends the data portion of frag to dst. It modifies
// frag and frag should not be used again.
func MergeFragment(dst, frag *PacketBuffer) {
	frag.buf.TrimFront(int64(frag.dataOffset()))
	dst.buf.Merge(&frag.buf)
}

// ReadFromVV moves at most count bytes from the beginning of srcVV to the end
// of d and returns the number of bytes moved.
func (d PacketData) ReadFromVV(srcVV *tcpipbuffer.VectorisedView, count int) int {
	done := 0
	for _, v := range srcVV.Views() {
		if len(v) < count {
			count -= len(v)
			done += len(v)
			d.pk.buf.AppendOwned(v)
		} else {
			v = v[:count]
			count -= len(v)
			done += len(v)
			d.pk.buf.Append(v)
			break
		}
	}
	srcVV.TrimFront(done)
	return done
}

// Size returns the number of bytes in the data payload of the packet.
func (d PacketData) Size() int {
	return int(d.pk.buf.Size()) - d.pk.dataOffset()
}

// AsRange returns a Range representing the current data payload of the packet.
func (d PacketData) AsRange() Range {
	return Range{
		pk:     d.pk,
		offset: d.pk.dataOffset(),
		length: d.Size(),
	}
}

// ExtractVV returns a VectorisedView of d. This method has the semantic to
// destruct the underlying packet, hence the packet cannot be used again.
//
// This method exists for compatibility between PacketBuffer and VectorisedView.
// It may be removed later and should be used with care.
func (d PacketData) ExtractVV() tcpipbuffer.VectorisedView {
	var vv tcpipbuffer.VectorisedView
	d.pk.buf.SubApply(d.pk.dataOffset(), d.pk.Size(), func(v []byte) {
		vv.AppendView(v)
	})
	return vv
}

// Range represents a contiguous subportion of a PacketBuffer.
type Range struct {
	pk     *PacketBuffer
	offset int
	length int
}

// Size returns the number of bytes in r.
func (r Range) Size() int {
	return r.length
}

// SubRange returns a new Range starting at off bytes of r. It returns an empty
// range if off is out-of-bounds.
func (r Range) SubRange(off int) Range {
	if off > r.length {
		return Range{pk: r.pk}
	}
	return Range{
		pk:     r.pk,
		offset: r.offset + off,
		length: r.length - off,
	}
}

// Capped returns a new Range with the same starting point of r and length
// capped at max.
func (r Range) Capped(max int) Range {
	if r.length <= max {
		return r
	}
	return Range{
		pk:     r.pk,
		offset: r.offset,
		length: max,
	}
}

// AsView returns the backing storage of r if possible. It will allocate a new
// View if r spans multiple pieces internally. Caller should not write to the
// returned View in any way.
func (r Range) AsView() tcpipbuffer.View {
	var allocated bool
	var v tcpipbuffer.View
	r.iterate(func(b []byte) {
		if v == nil {
			// v has not been assigned, allowing first view to be returned.
			v = b
		} else {
			// v has been assigned. This range spans more than a view, a new view
			// needs to be allocated.
			if !allocated {
				allocated = true
				all := make([]byte, 0, r.length)
				all = append(all, v...)
				v = all
			}
			v = append(v, b...)
		}
	})
	return v
}

// ToOwnedView returns a owned copy of data in r.
func (r Range) ToOwnedView() tcpipbuffer.View {
	if r.length == 0 {
		return nil
	}
	all := make([]byte, 0, r.length)
	r.iterate(func(b []byte) {
		all = append(all, b...)
	})
	return all
}

// Checksum calculates the RFC 1071 checksum for the underlying bytes of r.
func (r Range) Checksum() uint16 {
	var c header.Checksumer
	r.iterate(c.Add)
	return c.Checksum()
}

// iterate calls fn for each piece in r. fn is always called with a non-empty
// slice.
func (r Range) iterate(fn func([]byte)) {
	r.pk.buf.SubApply(r.offset, r.length, fn)
}

// PayloadSince returns packet payload starting from and including a particular
// header.
//
// The returned View is owned by the caller - its backing buffer is separate
// from the packet header's underlying packet buffer.
func PayloadSince(h PacketHeader) tcpipbuffer.View {
	offset := h.pk.headerOffset()
	for i := headerType(0); i < h.typ; i++ {
		offset += h.pk.headers[i].length
	}
	return Range{
		pk:     h.pk,
		offset: offset,
		length: int(h.pk.buf.Size()) - offset,
	}.ToOwnedView()
}
