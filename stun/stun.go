// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package STUN generates STUN request packets and parses response packets.
package stun

import (
	crand "crypto/rand"
	"errors"
	"hash/crc32"
)

var (
	attrSoftware = append([]byte{
		0x80, 0x22, // software header
		0x00, byte(len("tailnode")), // attr length
	}, "tailnode"...)
	lenMsg = byte(len(attrSoftware) + lenFingerprint) // number of bytes following header
)

const (
	bindingRequest = "\x00\x01"
	magicCookie    = "\x21\x12\xa4\x42"
	lenFingerprint = 8 // 2+byte header + 2-byte length + 4-byte crc32
	ipv4Len        = 4
	ipv6Len        = 16
	headerLen      = 20
)

// TxID is a transaction ID.
type TxID [12]byte

// NewTxID returns a new random TxID.
func NewTxID() TxID {
	var tx TxID
	if _, err := crand.Read(tx[:]); err != nil {
		panic(err)
	}
	return tx
}

// Request generates a binding request STUN packet.
// The transaction ID, tID, should be a random sequence of bytes.
func Request(tID TxID) []byte {
	// STUN header, RFC5389 Section 6.
	b := make([]byte, 0, headerLen+len(attrSoftware)+lenFingerprint)
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
// The returned addr slice is owned by the caller and does not alias b.
func ParseResponse(b []byte) (tID TxID, addr []byte, port uint16, err error) {
	if !Is(b) {
		return tID, nil, 0, ErrNotSTUN
	}
	copy(tID[:], b[8:headerLen])
	if b[0] != 0x01 || b[1] != 0x01 {
		return tID, nil, 0, ErrNotSuccessResponse
	}
	attrsLen := int(b[2])<<8 | int(b[3])
	b = b[headerLen:] // remove STUN header
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

func xorMappedAddress(tID TxID, b []byte) (addr []byte, port uint16, err error) {
	// XOR-MAPPED-ADDRESS attribute, RFC5389 Section 15.2
	if len(b) < 4 {
		return nil, 0, ErrMalformedAttrs
	}
	xorPort := uint16(b[2])<<8 | uint16(b[3])
	addrField := b[4:]
	port = xorPort ^ 0x2112 // first half of magicCookie

	addrLen := familyAddrLen(b[1])
	if addrLen == 0 {
		return nil, 0, ErrMalformedAttrs
	}
	if len(addrField) < addrLen {
		return nil, 0, ErrMalformedAttrs
	}
	xorAddr := addrField[:addrLen]
	addr = make([]byte, addrLen)
	for i := range xorAddr {
		if i < len(magicCookie) {
			addr[i] = xorAddr[i] ^ magicCookie[i]
		} else {
			addr[i] = xorAddr[i] ^ tID[i-len(magicCookie)]
		}
	}
	return addr, port, nil
}

func familyAddrLen(fam byte) int {
	switch fam {
	case 0x01: // IPv4
		return ipv4Len
	case 0x02: // IPv6
		return ipv6Len
	default:
		return 0
	}
}

func mappedAddress(b []byte) (addr []byte, port uint16, err error) {
	if len(b) < 4 {
		return nil, 0, ErrMalformedAttrs
	}
	port = uint16(b[2])<<8 | uint16(b[3])
	addrField := b[4:]
	addrLen := familyAddrLen(b[1])
	if addrLen == 0 {
		return nil, 0, ErrMalformedAttrs
	}
	if len(addrField) < addrLen {
		return nil, 0, ErrMalformedAttrs
	}
	return append([]byte(nil), addrField[:addrLen]...), port, nil
}

// Is reports whether b is a STUN message.
func Is(b []byte) bool {
	return len(b) >= headerLen &&
		b[0]&0b11000000 == 0 && // top two bits must be zero
		string(b[4:8]) == magicCookie
}
