// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Every message on the wire starts with a 24-byte header:
//
//	 0    6   magic       = "TSLBc\0"
//	 6    1   version     = 0x01
//	 7    1   msg_type    = 0x01 Beacon | 0x02 Approval | 0x03 SealedURL
//	 8   16   request_id  = per-session ID chosen by the requester
//
// Payload layout after the header is per-type; see the parse* functions.

const (
	magic      = "TSLBc\x00"
	version    = 0x01
	headerSize = 24

	maxHostname   = 63
	maxDeviceKind = 31
	maxWireSize   = 1200 // one datagram, comfortably below any LAN MTU
)

type msgType byte

const (
	msgTypeBeacon    msgType = 0x01
	msgTypeApproval  msgType = 0x02
	msgTypeSealedURL msgType = 0x03
)

type requestID [16]byte

type beaconMsg struct {
	RequestID    requestID
	SenderEphPub [32]byte
	UnixSec      int64
	Hostname     string
	DeviceKind   string
	DeviceIDHash [16]byte // SHA-256(raw device id), truncated
}

type approvalMsg struct {
	RequestID      requestID
	ApproverEphPub [32]byte
	UnixSec        int64
	ApproverName   string
}

type sealedURLMsg struct {
	RequestID  requestID
	Nonce      [12]byte
	Ciphertext []byte // AEAD-sealed; request_id is the AAD
}

var (
	errShortHeader   = errors.New("loginbeacon: buffer shorter than header")
	errBadMagic      = errors.New("loginbeacon: bad magic")
	errBadVersion    = errors.New("loginbeacon: unsupported version")
	errBadLength     = errors.New("loginbeacon: message length mismatch")
	errBadHostname   = errors.New("loginbeacon: hostname too long")
	errBadDeviceKind = errors.New("loginbeacon: device kind too long")
	errBadType       = errors.New("loginbeacon: unknown message type")
)

func parseHeader(buf []byte) (msgType, requestID, error) {
	var rid requestID
	if len(buf) < headerSize {
		return 0, rid, errShortHeader
	}
	if string(buf[:6]) != magic {
		return 0, rid, errBadMagic
	}
	if buf[6] != version {
		return 0, rid, errBadVersion
	}
	t := msgType(buf[7])
	switch t {
	case msgTypeBeacon, msgTypeApproval, msgTypeSealedURL:
	default:
		return 0, rid, errBadType
	}
	copy(rid[:], buf[8:24])
	return t, rid, nil
}

func writeHeader(buf []byte, t msgType, rid requestID) {
	copy(buf[:6], magic)
	buf[6] = version
	buf[7] = byte(t)
	copy(buf[8:24], rid[:])
}

func marshalBeacon(m *beaconMsg) ([]byte, error) {
	if len(m.Hostname) > maxHostname {
		return nil, errBadHostname
	}
	if len(m.DeviceKind) > maxDeviceKind {
		return nil, errBadDeviceKind
	}
	size := headerSize + 32 + 8 + 1 + len(m.Hostname) + 1 + len(m.DeviceKind) + 16
	if size > maxWireSize {
		return nil, errBadLength
	}
	buf := make([]byte, size)
	writeHeader(buf, msgTypeBeacon, m.RequestID)
	off := headerSize
	copy(buf[off:off+32], m.SenderEphPub[:])
	off += 32
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(m.UnixSec))
	off += 8
	buf[off] = byte(len(m.Hostname))
	off++
	copy(buf[off:off+len(m.Hostname)], m.Hostname)
	off += len(m.Hostname)
	buf[off] = byte(len(m.DeviceKind))
	off++
	copy(buf[off:off+len(m.DeviceKind)], m.DeviceKind)
	off += len(m.DeviceKind)
	copy(buf[off:off+16], m.DeviceIDHash[:])
	return buf, nil
}

func parseBeacon(buf []byte) (*beaconMsg, error) {
	_, rid, err := parseHeader(buf)
	if err != nil {
		return nil, err
	}
	if len(buf) < headerSize+32+8+1+1+16 {
		return nil, errBadLength
	}
	m := &beaconMsg{RequestID: rid}
	off := headerSize
	copy(m.SenderEphPub[:], buf[off:off+32])
	off += 32
	m.UnixSec = int64(binary.BigEndian.Uint64(buf[off : off+8]))
	off += 8

	hlen := int(buf[off])
	off++
	if hlen > maxHostname || off+hlen > len(buf) {
		return nil, errBadLength
	}
	m.Hostname = string(buf[off : off+hlen])
	off += hlen

	if off >= len(buf) {
		return nil, errBadLength
	}
	klen := int(buf[off])
	off++
	if klen > maxDeviceKind || off+klen > len(buf) {
		return nil, errBadLength
	}
	m.DeviceKind = string(buf[off : off+klen])
	off += klen

	if off+16 != len(buf) {
		return nil, errBadLength
	}
	copy(m.DeviceIDHash[:], buf[off:off+16])
	return m, nil
}

func marshalApproval(m *approvalMsg) []byte {
	name := m.ApproverName
	if len(name) > maxHostname {
		name = name[:maxHostname]
	}
	buf := make([]byte, headerSize+32+8+1+len(name))
	writeHeader(buf, msgTypeApproval, m.RequestID)
	off := headerSize
	copy(buf[off:off+32], m.ApproverEphPub[:])
	off += 32
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(m.UnixSec))
	off += 8
	buf[off] = byte(len(name))
	off++
	copy(buf[off:off+len(name)], name)
	return buf
}

func parseApproval(buf []byte) (*approvalMsg, error) {
	_, rid, err := parseHeader(buf)
	if err != nil {
		return nil, err
	}
	const fixed = headerSize + 32 + 8 + 1
	if len(buf) < fixed {
		return nil, errBadLength
	}
	m := &approvalMsg{RequestID: rid}
	off := headerSize
	copy(m.ApproverEphPub[:], buf[off:off+32])
	off += 32
	m.UnixSec = int64(binary.BigEndian.Uint64(buf[off : off+8]))
	off += 8
	nlen := int(buf[off])
	off++
	if nlen > maxHostname || off+nlen != len(buf) {
		return nil, errBadLength
	}
	m.ApproverName = string(buf[off : off+nlen])
	return m, nil
}

func marshalSealedURL(m *sealedURLMsg) ([]byte, error) {
	size := headerSize + 12 + len(m.Ciphertext)
	if size > maxWireSize {
		return nil, errBadLength
	}
	buf := make([]byte, size)
	writeHeader(buf, msgTypeSealedURL, m.RequestID)
	off := headerSize
	copy(buf[off:off+12], m.Nonce[:])
	off += 12
	copy(buf[off:], m.Ciphertext)
	return buf, nil
}

func parseSealedURL(buf []byte) (*sealedURLMsg, error) {
	_, rid, err := parseHeader(buf)
	if err != nil {
		return nil, err
	}
	if len(buf) < headerSize+12 {
		return nil, errBadLength
	}
	m := &sealedURLMsg{RequestID: rid}
	off := headerSize
	copy(m.Nonce[:], buf[off:off+12])
	off += 12
	m.Ciphertext = append([]byte(nil), buf[off:]...)
	return m, nil
}

func (t msgType) String() string {
	switch t {
	case msgTypeBeacon:
		return "beacon"
	case msgTypeApproval:
		return "approval"
	case msgTypeSealedURL:
		return "sealed-url"
	default:
		return fmt.Sprintf("msgType(%d)", byte(t))
	}
}
