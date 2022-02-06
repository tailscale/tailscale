// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package header

import "encoding/binary"

// These constants are declared in linux/virtio_net.h.
const (
	_VIRTIO_NET_HDR_F_NEEDS_CSUM = 1
	_VIRTIO_NET_HDR_GSO_NONE     = 0
	_VIRTIO_NET_HDR_GSO_TCPV4    = 1
	_VIRTIO_NET_HDR_GSO_TCPV6    = 4
)

const (
	// VirtioNetHeaderSize is the size of VirtioNetHeader in bytes.
	VirtioNetHeaderSize = 10
)

// Offsets for fields in the virtio net header.
const (
	flags      = 0
	gsoType    = 1
	hdrLen     = 2
	gsoSize    = 4
	csumStart  = 6
	csumOffset = 8
)

// VirtioNetHeaderFields is the Go equivalent of the struct declared in
// linux/virtio_net.h.
type VirtioNetHeaderFields struct {
	Flags      uint8
	GSOType    uint8
	HdrLen     uint16
	GSOSize    uint16
	CSumStart  uint16
	CSumOffset uint16
}

// VirtioNetHeader represents a virtio net header stored in a byte array.
type VirtioNetHeader []byte

// Flags returns the "flags" field of the virtio net header.
func (v VirtioNetHeader) Flags() uint8 {
	return uint8(v[flags])
}

// GSOType returns the "gsoType" field of the virtio net header.
func (v VirtioNetHeader) GSOType() uint8 {
	return uint8(v[gsoType])
}

// HdrLen returns the "hdrLen" field of the virtio net header.
func (v VirtioNetHeader) HdrLen() uint16 {
	return binary.BigEndian.Uint16(v[hdrLen:])
}

// GSOSize returns the "gsoSize" field of the virtio net header.
func (v VirtioNetHeader) GSOSize() uint16 {
	return binary.BigEndian.Uint16(v[gsoSize:])
}

// CSumStart returns the "csumStart" field of the virtio net header.
func (v VirtioNetHeader) CSumStart() uint16 {
	return binary.BigEndian.Uint16(v[csumStart:])
}

// CSumOffset returns the "csumOffset" field of the virtio net header.
func (v VirtioNetHeader) CSumOffset() uint16 {
	return binary.BigEndian.Uint16(v[csumOffset:])
}

// Encode encodes all the fields of the virtio net header.
func (v VirtioNetHeader) Encode(f *VirtioNetHeaderFields) {
	v[flags] = uint8(f.Flags)
	v[gsoType] = uint8(f.GSOType)
	binary.BigEndian.PutUint16(v[hdrLen:], f.HdrLen)
	binary.BigEndian.PutUint16(v[gsoSize:], f.GSOSize)
	binary.BigEndian.PutUint16(v[csumStart:], f.CSumStart)
	binary.BigEndian.PutUint16(v[csumOffset:], f.CSumOffset)
}
