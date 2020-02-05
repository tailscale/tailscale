// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package STUN generates STUN request packets and parses response packets.
package stun

import (
	"bytes"
	"errors"
	"hash/crc32"
)

var (
	bindingRequest = []byte{0x00, 0x01}
	magicCookie    = []byte{0x21, 0x12, 0xa4, 0x42}
	attrSoftware   = append([]byte{
		0x80, 0x22, // software header
		0x00, byte(len("tailnode")), // attr length
	}, "tailnode"...)
	lenMsg = byte(len(attrSoftware) + lenFingerprint) // number of bytes following header
)

const lenFingerprint = 8 // 2+byte header + 2-byte length + 4-byte crc32

// Request generates a binding request STUN packet.
// The transaction ID, tID, should be a random sequence of bytes.
func Request(tID [12]byte) []byte {
	// STUN header, RFC5389 Section 6.
	b := make([]byte, 0, 20+len(attrSoftware)+lenFingerprint)
	b = append(b, bindingRequest...)
	b = append(b, 0x00, lenMsg)
	b = append(b, magicCookie...)
	b = append(b, tID[:]...)

	// Attribute SOFTWARE, RFC5389 Section 15.5.
	b = append(b, attrSoftware...)

	// Attribute FINGERPRINT, RFC5389 Section 15.5.
	fp := crc32.ChecksumIEEE(b) ^ 0x5354554e
	b = append(b, 0x80, 0x28) // fingerprint header
	b = append(b, 0x00, 0x04) // fingerprint length
	b = append(b,
		byte(fp>>24),
		byte(fp>>16),
		byte(fp>>8),
		byte(fp),
	)

	return b
}

var (
	ErrNotSTUN            = errors.New("response is not a STUN packet")
	ErrNotSuccessResponse = errors.New("STUN response error")
	ErrMalformedAttrs     = errors.New("STUN response has malformed attributes")
)

// ParseResponse parses a successful binding response STUN packet.
// The IP address is extracted from the XOR-MAPPED-ADDRESS attribute.
func ParseResponse(b []byte) (tID [12]byte, addr []byte, port uint16, err error) {
	if !Is(b) {
		return tID, nil, 0, ErrNotSTUN
	}
	copy(tID[:], b[8:20])
	if b[0] != 0x01 || b[1] != 0x01 {
		return tID, nil, 0, ErrNotSuccessResponse
	}
	attrsLen := int(b[2])<<8 | int(b[3])
	b = b[20:] // remove STUN header
	if attrsLen > len(b) {
		return tID, nil, 0, ErrMalformedAttrs
	} else if len(b) > attrsLen {
		b = b[:attrsLen] // trim trailing packet bytes
	}

	var addr6, fallbackAddr, fallbackAddr6 []byte
	var port6, fallbackPort, fallbackPort6 uint16

	// Read through the attributes.
	// The the addr+port reported by XOR-MAPPED-ADDRESS
	// as the canonical value. If the attribute is not
	// present but the STUN server responds with
	// MAPPED-ADDRESS we fall back to it.
	for len(b) > 0 {
		if len(b) < 4 {
			return tID, nil, 0, ErrMalformedAttrs
		}
		attrType := uint16(b[0])<<8 | uint16(b[1])
		attrLen := int(b[2])<<8 | int(b[3])
		attrLenPad := attrLen % 4
		if attrLen+attrLenPad > len(b)-4 {
			return tID, nil, 0, ErrMalformedAttrs
		}
		b = b[4:]

		const typeMappedAddress = 0x0001
		const typeXorMappedAddress = 0x0020
		// This alternative attribute type is not
		// mentioned in the RFC, but the shift into
		// the "comprehension-optional" range seems
		// like an easy mistake for a server to make.
		// And servers appear to send it.
		const typeXorMappedAddressAlt = 0x8020
		switch attrType {
		case typeXorMappedAddress, typeXorMappedAddressAlt:
			a, p, err := xorMappedAddress(tID, b[:attrLen])
			if err != nil {
				return tID, nil, 0, ErrMalformedAttrs
			}
			if len(a) == 16 {
				addr6, port6 = a, p
			} else {
				addr, port = a, p
			}
		case typeMappedAddress:
			a, p, err := mappedAddress(b[:attrLen])
			if err != nil {
				return tID, nil, 0, ErrMalformedAttrs
			}
			if len(a) == 16 {
				fallbackAddr6, fallbackPort6 = a, p
			} else {
				fallbackAddr, fallbackPort = a, p
			}
		}

		b = b[attrLen+attrLenPad:]
	}

	if addr != nil {
		return tID, addr, port, nil
	}
	if fallbackAddr != nil {
		return tID, append([]byte{}, fallbackAddr...), fallbackPort, nil
	}
	if addr6 != nil {
		return tID, addr6, port6, nil
	}
	if fallbackAddr6 != nil {
		return tID, append([]byte{}, fallbackAddr6...), fallbackPort6, nil
	}
	return tID, nil, 0, ErrMalformedAttrs
}

func xorMappedAddress(tID [12]byte, b []byte) (addr []byte, port uint16, err error) {
	// XOR-MAPPED-ADDRESS attribute, RFC5389 Section 15.2
	if len(b) < 8 {
		return nil, 0, ErrMalformedAttrs
	}
	xorPort := uint16(b[2])<<8 | uint16(b[3])
	port = xorPort ^ 0x2112 // first half of magicCookie

	switch ipFamily := b[1]; ipFamily { // RFC5389 Section 15.1
	case 0x01: // IPv4
		addr = make([]byte, 4)
		xorAddr := b[4 : 4+len(addr)]
		for i := range xorAddr {
			addr[i] = xorAddr[i] ^ magicCookie[i]
		}
	case 0x02: // IPv6
		addr = make([]byte, 16)
		xorAddr := b[4 : 4+len(addr)]
		for i := range xorAddr {
			addr[i] = xorAddr[i] ^ magicCookie[i]
		}
		for i := 4; i < len(addr); i++ {
			addr[i] = xorAddr[i] ^ tID[4-i]
		}
	default:
		return nil, 0, ErrMalformedAttrs
	}
	if len(b) < 4+len(addr) {
		return nil, 0, ErrMalformedAttrs
	}
	return addr, port, err
}

func mappedAddress(b []byte) (addr []byte, port uint16, err error) {
	if len(b) < 8 {
		return nil, 0, ErrMalformedAttrs
	}
	port = uint16(b[2])<<8 | uint16(b[3])

	switch ipFamily := b[1]; ipFamily { // RFC5389 Section 15.1
	case 0x01: // IPv4
		addr = b[4 : 4+4]
	case 0x02: // IPv6
		addr = b[4 : 4+16]
	default:
		return nil, 0, ErrMalformedAttrs
	}
	return addr, port, err
}

// Is reports whether b is a STUN message.
func Is(b []byte) bool {
	if len(b) < 20 {
		return false // every STUN message must have a 20-byte header
	}
	// TODO RFC5389 suggests checking the first 2 bits of the header are zero.
	if !bytes.Equal(b[4:8], magicCookie) {
		return false
	}
	return true
}
