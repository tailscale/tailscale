// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package tsdns

import (
	"encoding/binary"
	"strings"
)

var bin = binary.BigEndian

// This file contains functionality necessary to convert messages
// to and from the DNS wire format. It is a lightweight alternative
// to github.com/miekg/dns, which increases the size of tailscaled by 2.5MB.

const (
	headerSize = 12
	// name "\x00" (ROOT) + Type + Class
	minQuestionSize = 1 + 2 + 2
	// name "\x00" (ROOT) + Type + Class + TTL + Length + IPv4
	minAnswerSize = 1 + 2 + 2 + 4 + 2 + 4
	// header + question
	minQuerySize = headerSize + minQuestionSize
	// header + question + answer
	minResponseSize = headerSize + minQuestionSize + minAnswerSize
)

const (
	flagAnswer             = 0b1000_0000_0000_0000
	maskOpcode             = 0b0111_1000_0000_0000
	flagAuthoritative      = 0b0000_0100_0000_0000
	flagTruncated          = 0b0000_0010_0000_0000
	flagRecursionDesired   = 0b0000_0001_0000_0000
	flagRecursionAvailable = 0b0000_0000_1000_0000
	flagAuthenticated      = 0b0000_0000_0010_0000
	flagAcceptNoAuth       = 0b0000_0000_0001_0000
	maskReplyCode          = 0b0000_0000_0000_1111
)

const defaultTTL = 3600

const classIN = 0x01

const opcodeStdQuery = 0

const typeA = 0x01

// question is an DNS question of type/class A IN
type question struct {
	Name []byte
}

// NameString returns a string representation of q.Name. For example:
//  []byte("\x03name\x03ipn\x03dev") -> "name.ipn.dev"
func (q *question) NameString() string {
	var sb strings.Builder
	numParts := q.Name[0]
	for _, b := range q.Name[1:] {
		if b == numParts {
			sb.WriteByte('.')
		} else {
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

// answer is an DNS answer of type/class A IN
type answer struct {
	IP []byte
}

type header struct {
	TransactionID uint16
	Flags         uint16
}

// message DNs
type message struct {
	Header   header
	Question question
	Answer   answer
}

// queryToReply converts m from a DNS query to a reply to that query in place.
func (m *message) queryToReply() {
	m.Header.Flags |= flagAnswer
	// Claim we are a recursive resolver if that is desired.
	if m.Header.Flags&flagRecursionDesired != 0 {
		m.Header.Flags |= flagRecursionAvailable
	}
	// Claim our response is authenticated if auth is required.
	if m.Header.Flags&flagAcceptNoAuth == 0 {
		m.Header.Flags |= flagAuthenticated
	}
}

// readQuery extracts important parts of a DNS query into a message struct.
//
// The structure of a DNS query is as follows:
// (c for copy to response, x for don't care)
//
//      0123 4567 89ab cdef 0123 4567 89ab cdef
//      ┌───────────────────┬───────────────────┐
//      │   Transaction ID  │       Flags       │
//   0  │         c         │0000 0xxc xxcx xxxx│
//      ├───────────────────┼───────────────────┤
//      │   Question count  │  Answer RR count  │
//   4  │         1         │         0         │
//      ├───────────────────┼───────────────────┤
//      │Authority RR count │Additional RR count│
//   8  │         x         │         x         │
//      ├───────────────────┴───────────────────┤
//      │              Question 0               │
//      ├───────────────────────────────────────┤
//      │                 Name                  │
//  12  │              c (n bytes)              │
//      │                                       │
//      │              name.ipn.dev             │
//      │                   ↕                   │
//      │      \x03name\x03ipn\x03dev\x00       │
//      ├───────────────────┬───────────────────┤
//      │       Type        │       Class       │
// 12+n │     0x01 (A)      │     0x01 (IN)     │
//      ├───────────────────┴───────────────────┤
// 16+n │                  ...                  │
//      └───────────────────────────────────────┘
func readQuery(m *message, in []byte) error {
	if len(in) < minQuerySize {
		return errTooSmall
	}

	m.Header.TransactionID = bin.Uint16(in[0:2])

	m.Header.Flags = bin.Uint16(in[2:4])
	if m.Header.Flags&flagAnswer != 0 || m.Header.Flags&maskOpcode != opcodeStdQuery {
		return errNotQuery
	}

	numQuestions := bin.Uint16(in[4:6])
	if numQuestions != 1 {
		return errNotOneQuestion
	}

	// Skip Answer/Authority/Additional RR counts (in[6:12])
	var offset int
	for offset = headerSize; offset < len(in); offset++ {
		if in[offset] == 0 {
			break
		}
	}
	m.Question.Name = in[headerSize:offset]
	offset += 1

	if len(in) < offset+4 {
		return errIncomplete
	}

	typ := bin.Uint16(in[offset : offset+2])
	class := bin.Uint16(in[offset+2 : offset+4])
	if typ != typeA || class != classIN {
		return errUnknownTypeClass
	}

	return nil
}

// writeReply assembles a DNS reply packet from a message struct.
// It returns the number of bytes written or an error.
//
// The structure of a DNS reply is as follows:
// (c for copied from query, x for don't care)
//
//       0123 4567 89ab cdef 0123 4567 89ab cdef
//      ┌───────────────────┬───────────────────┐
//      │   Transaction ID  │       Flags       │
//   0  │         c         │1000 0xxc xxcx xxxx│
//      ├───────────────────┼───────────────────┤
//      │   Question count  │  Answer RR count  │
//   4  │         1         │         1         │
//      ├───────────────────┼───────────────────┤
//      │Authority RR count │Additional RR count│
//   8  │         0         │         0         │
//      ├───────────────────┴───────────────────┤
//      │              Question 0               │
//      ├───────────────────────────────────────┤
//      │                 Name                  │
//  12  │              c (n bytes)              │
//      │                                       │
//      │              name.ipn.dev             │
//      │                   ↕                   │
//      │      \x03name\x03ipn\x03dev\x00       │
//      ├───────────────────┬───────────────────┤
//      │       Type        │       Class       │
// 12+n │     0x01 (A)      │     0x01 (IN)     │
//      ├───────────────────┴───────────────────┤
//      │               Answer 0                │
//      ├───────────────────────────────────────┤
//      │                 Name                  │
// 16+n │              c (n bytes)              │
//      │                                       │
//      │              name.ipn.dev             │
//      │                   ↕                   │
//      │      \x03name\x03ipn\x03dev\x00       │
//      ├───────────────────┬───────────────────┤
//      │       Type        │       Class       │
// 16+2n│     0x01 (A)      │     0x01 (IN)     │
//      ├───────────────────┴───────────────────┤
//      │                  TTL                  │
// 20+2n│                 3600                  │
//      ├───────────────────┬───────────────────┤
//      │       Length      │         IP        │
// 24+2n│        0x04       │      100.xxx      │
//      ├───────────────────┼───────────────────┤
//      │         IP        │///////////////////│
// 28+2n│      yyy.zzz      │///////////////////│
//      └───────────────────┴───────────────────┘
func writeReply(m *message, out []byte) (int, error) {
	if len(out) < minResponseSize+len(m.Question.Name) {
		return 0, errSmallBuffer
	}

	bin.PutUint16(out[0:2], m.Header.TransactionID)
	bin.PutUint16(out[2:4], m.Header.Flags)
	// One question, one answer
	bin.PutUint16(out[4:6], 1)
	bin.PutUint16(out[6:8], 1)
	// No authority or additional RRs
	bin.PutUint16(out[8:12], 0)

	// Write question
	offset := 12
	n := copy(out[offset:], m.Question.Name)
	offset += n
	out[offset] = 0
	offset += 1
	bin.PutUint16(out[offset+0:offset+2], typeA)
	bin.PutUint16(out[offset+2:offset+4], classIN)
	offset += 4

	// Write answer
	n = copy(out[offset:], m.Question.Name)
	offset += n
	out[offset] = 0
	offset += 1
	bin.PutUint16(out[offset+0:offset+2], typeA)
	bin.PutUint16(out[offset+2:offset+4], classIN)
	bin.PutUint32(out[offset+4:offset+8], defaultTTL)
	bin.PutUint16(out[offset+8:offset+10], uint16(len(m.Answer.IP)))
	offset += 10
	n = copy(out[offset:], m.Answer.IP)
	offset += n

	return offset, nil
}
