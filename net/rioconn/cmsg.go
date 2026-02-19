// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rioconn

import (
	"fmt"
	"iter"
	"unsafe"
)

// _RIO_CMSG_BUFFER is the header of the control messages buffer for RIO operations,
// as defined by the Windows API. It is followed by zero or more control messages.
type _RIO_CMSG_BUFFER struct {
	totalLength uint32 // total length of the buffer, including this header
	// followed by control messages aligned to _WSA_CMSGHDR_ALIGN
}

// _WSACMSGHDR is the header for a single control message, as defined by the Windows API.
type _WSACMSGHDR struct {
	len   uintptr
	level int32
	typ   int32
	// followed by data aligned to _WSA_CMSGDATA_ALIGN
}

const (
	_MAX_NATURAL_ALIGN  = unsafe.Alignof(uintptr(0))
	_WSA_CMSGHDR_ALIGN  = unsafe.Alignof(_WSACMSGHDR{})
	_WSA_CMSGDATA_ALIGN = _MAX_NATURAL_ALIGN
	_RIO_CMSG_BASE_SIZE = (unsafe.Sizeof(_RIO_CMSG_BUFFER{}) +
		(_WSA_CMSGHDR_ALIGN - 1)) &^ (_WSA_CMSGHDR_ALIGN - 1)
)

const (
	// controlMessagesSize is the target size of the [controlMessages] struct,
	// which includes the header, padding for alignment, and space for control messages.
	// It is somewhat arbitrary but is large enough to hold typical control messages.
	controlMessagesSize = 64

	// controlMessagesBufferSize is the size of the buffer for control messages,
	// which is the total size minus the size of the header.
	controlMessagesBufferSize = controlMessagesSize - unsafe.Sizeof(_RIO_CMSG_BUFFER{})
)

// controlMessages is a fixed-size control messages buffer for RIO operations.
// It is large enough to hold the header and typical control messages
// for either send or receive operations.
type controlMessages struct {
	_RIO_CMSG_BUFFER
	_ [controlMessagesBufferSize]byte // space for cmsgs
}

// controlMessage represents a single control message.
type controlMessage struct {
	Level int32  // protocol that originated the control information
	Type  int32  // protocol-specific type of control information
	Data  []byte // type-specific control data (backed by [controlMessages.buffer])
}

// Empty reports whether the control messages buffer contains no control messages.
func (cmsgs *controlMessages) Empty() bool {
	return uintptr(cmsgs.totalLength) <= _RIO_CMSG_BASE_SIZE
}

// All returns an iterator over all control messages in the buffer.
func (cmsgs *controlMessages) All() iter.Seq[controlMessage] {
	return func(yield func(cmsg controlMessage) bool) {
		offset := _RIO_CMSG_BASE_SIZE
		totalLen := uintptr(cmsgs.totalLength)
		if totalLen > unsafe.Sizeof(*cmsgs) {
			panic("controlMessages buffer overflow")
		}
		for offset+unsafe.Sizeof(_WSACMSGHDR{}) <= totalLen {
			hdr := (*_WSACMSGHDR)(unsafe.Add(unsafe.Pointer(cmsgs), offset))
			dataOffset := alignUp(unsafe.Sizeof(_WSACMSGHDR{}), _WSA_CMSGDATA_ALIGN)
			if hdr.len < dataOffset || offset+hdr.len > totalLen {
				panic("invalid control message header length")
			}
			dataLen := uintptr(hdr.len) - dataOffset
			data := unsafe.Slice((*byte)(
				unsafe.Add(unsafe.Pointer(hdr), dataOffset)),
				dataLen,
			)
			if !yield(controlMessage{
				Level: hdr.level,
				Type:  hdr.typ,
				Data:  data,
			}) {
				break
			}
			offset += alignUp(hdr.len, _WSA_CMSGHDR_ALIGN)
		}
	}
}

// GetOk retrieves the data for the first control message with the given
// level and type. It reports whether such a control message was found.
func (cmsgs *controlMessages) GetOk(level, ctype int32) (data []byte, ok bool) {
	for cmsg := range cmsgs.All() {
		if cmsg.Level == level && cmsg.Type == ctype {
			return cmsg.Data, true
		}
	}
	return nil, false
}

// GetUInt32Ok is like GetOk but interprets the data as a uint32.
func (cmsgs *controlMessages) GetUInt32Ok(level, ctype int32) (val uint32, ok bool) {
	data, ok := cmsgs.GetOk(level, ctype)
	if !ok || len(data) < 4 {
		return 0, false
	}
	return *(*uint32)(unsafe.Pointer(unsafe.SliceData(data))), true
}

// GetUInt32 is like GetUInt32Ok, but returns zero if the specified control
// message is not found.
func (cmsgs *controlMessages) GetUInt32(level, ctype int32) uint32 {
	val, _ := cmsgs.GetUInt32Ok(level, ctype)
	return val
}

// Append adds a control message with the given level, type, and data to the
// buffer. It returns an error if there is not enough space.
func (cmsgs *controlMessages) Append(level, ctype int32, data []byte) error {
	space := alignUp(
		unsafe.Sizeof(_WSACMSGHDR{})+
			alignUp(uintptr(len(data)), _WSA_CMSGDATA_ALIGN),
		_WSA_CMSGHDR_ALIGN,
	)
	// Append the new control message at the end of the existing messages,
	// or after the base header if there are no existing messages.
	offset := max(uintptr(cmsgs.totalLength), _RIO_CMSG_BASE_SIZE)
	if space > unsafe.Sizeof(*cmsgs)-offset {
		return fmt.Errorf("not enough space to append cmsg (Level=%d Type=%d Len=%d)", level, ctype, len(data))
	}
	hdr := (*_WSACMSGHDR)(unsafe.Add(unsafe.Pointer(cmsgs), offset))
	hdr.level = level
	hdr.typ = ctype
	hdr.len = alignUp(unsafe.Sizeof(_WSACMSGHDR{}), _WSA_CMSGDATA_ALIGN) + uintptr(len(data))
	dataPtr := unsafe.Add(
		unsafe.Pointer(hdr),
		alignUp(unsafe.Sizeof(_WSACMSGHDR{}), _WSA_CMSGDATA_ALIGN),
	)
	copy(unsafe.Slice((*byte)(dataPtr), len(data)), data)
	cmsgs.totalLength = uint32(offset + space)
	return nil
}

// AppendUInt32 is like Append but appends a uint32 value.
func (cmsgs *controlMessages) AppendUInt32(level, ctype int32, val uint32) error {
	data := (*[4]byte)(unsafe.Pointer(&val))[:]
	return cmsgs.Append(level, ctype, data)
}

// Clear removes all control messages from the buffer.
func (cmsgs *controlMessages) Clear() {
	cmsgs.totalLength = uint32(_RIO_CMSG_BASE_SIZE)
}

// Bytes returns the raw bytes of the control messages buffer.
func (cmsgs *controlMessages) Bytes() []byte {
	totalLen := min(uintptr(cmsgs.totalLength), unsafe.Sizeof(*cmsgs))
	return unsafe.Slice((*byte)(unsafe.Pointer(cmsgs)), totalLen)
}

// Buffer returns the entire control messages buffer, including unused space.
func (cmsgs *controlMessages) Buffer() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(cmsgs)), unsafe.Sizeof(*cmsgs))
}
