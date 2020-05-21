// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsdns provides a Resolver struct capable of resolving
// domains on a Taiscale network.
package tsdns

import (
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/packet"
)

const (
	// MaxQuerySize is the maximal size of a Magic DNS query.
	MaxQuerySize = 512
	// MaxResponseSize is the maximal size of a Magic DNS response.
	MaxResponseSize = 512
)

const (
	ipOffset      = device.MessageTransportHeaderSize
	dnsDataOffset = ipOffset + packet.UDPDataOffset

	bufferSize = dnsDataOffset + MaxResponseSize
)

// Resolver is a
type Resolver struct {
	logf logger.Logf

	// ip is the IP on which the resolver is listening (default 100.100.100.100).
	ip packet.IP
	// port is the port on which the resolver is listening (default 53).
	port uint16

	// responseBuffer to avoid graticious allocations.
	responseBuffer [bufferSize]byte
}

// NewResolver constructs a resolver with default parameters.
func NewResolver(logf logger.Logf) *Resolver {
	return &Resolver{
		logf: logf,
		ip:   packet.IP(binary.BigEndian.Uint32([]byte{100, 100, 100, 100})),
		port: uint16(53),
	}
}

// AcceptsPacket determines if the given packet is a DNS request
// directed to this resolver (by ip and port).
// We also require that UDP be used to simplify things for now.
func (r *Resolver) AcceptsPacket(in *packet.QDecode) bool {
	return in.DstIP == r.ip && in.DstPort == r.port && in.IPProto == packet.UDP
}

var (
	ErrIncomplete       = errors.New("query incomplete")
	ErrNotOurName       = errors.New("not an *.ipn.dev domain")
	ErrNotQuery         = errors.New("not a DNS query")
	ErrNotOneQuestion   = errors.New("query does not have exactly one question")
	ErrSmallBuffer      = errors.New("buffer too small to hold DNS reply")
	ErrTooSmall         = errors.New("packet too small to be a DNS query")
	ErrQueryHasAnswers  = errors.New("query has answers")
	ErrUnknownTypeClass = errors.New("question has unrecognized class/type")
)

// Respond generates a response to the given packet.
// It is assumed that r.AcceptsPacket(query) is true.
func (r *Resolver) Respond(query *packet.QDecode) ([]byte, error) {
	var msg message

	// Extract the UDP payload.
	in := query.Sub(packet.UDPHeaderSize, MaxQuerySize)

	err := readQuery(&msg, in)
	if err != nil {
		return nil, err
	}

	// ###.ipn.dev
	name := msg.Question.NameString()
	if len(name) != 11 || name[3:] != ".ipn.dev" {
		return nil, ErrNotOurName
	}
	lastOctet, err := strconv.Atoi(name[:3])
	if err != nil || lastOctet < 0 || lastOctet > 255 {
		return nil, ErrNotOurName
	}

	msg.queryToReply()
	msg.Answer.IP = []byte{100, 0, 64, byte(lastOctet)}

	n, err := writeReply(&msg, r.responseBuffer[dnsDataOffset:])
	if err != nil {
		return nil, err
	}
	end := dnsDataOffset + n

	// Flip the bits in the ipID.
	// If incoming ipIDs are distinct, then so are these.
	ipID := ^binary.BigEndian.Uint16(query.Sub(2, 4))
	// Failure is impossible: r.responseBuffer has statically sufficient size.
	packet.WriteUDPHeader(
		query.DstIP, query.SrcIP, ipID, query.DstPort, query.SrcPort,
		r.responseBuffer[ipOffset:end],
	)

	return r.responseBuffer[:end], nil
}
