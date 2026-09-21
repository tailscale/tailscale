// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dnscache

import (
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// fuzzQuery builds a DNS query header passing getDNSQueryCacheKey's header
// checks, so fuzz mutations target the question section.
func fuzzQuery(txID uint16, question []byte) []byte {
	msg := make([]byte, 12, 12+len(question))
	binary.BigEndian.PutUint16(msg[0:2], txID)
	binary.BigEndian.PutUint16(msg[4:6], 1)  // numQ
	binary.BigEndian.PutUint16(msg[6:8], 0)  // numAns
	binary.BigEndian.PutUint16(msg[8:10], 0) // numAuth
	return append(msg, question...)
}

// fuzzQuestion packs only the question section (QNAME/QTYPE/QCLASS) for name, without a header.
func fuzzQuestion(name string, typ dnsmessage.Type) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	if err := b.StartQuestions(); err != nil {
		panic(err)
	}
	err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  typ,
		Class: dnsmessage.ClassINET,
	})
	if err != nil {
		panic(err)
	}
	msg, err := b.Finish()
	if err != nil {
		panic(err)
	}
	return msg[12:]
}

// fuzzMaxLabelName returns a name with a 63-byte label, the wire limit.
func fuzzMaxLabelName() string {
	return strings.Repeat("a", 63) + ".example.com."
}

// fuzzMaxQName returns a 255-byte encoded name, the whole-QNAME wire limit.
func fuzzMaxQName() string {
	return strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61) + "."
}

func FuzzGetDNSQueryCacheKey(f *testing.F) {
	// Valid queries for common record types
	f.Add(makeQ(0x1234, "foo.com."))
	f.Add(fuzzQuery(0x1234, fuzzQuestion("a.", dnsmessage.TypeA)))
	f.Add(fuzzQuery(0xffff, fuzzQuestion("x.y.example.com.", dnsmessage.TypeAAAA)))
	f.Add(fuzzQuery(0xbeef, fuzzQuestion("mx.example.com.", dnsmessage.TypeMX)))
	f.Add(fuzzQuery(0x0001, fuzzQuestion("txt.example.com.", dnsmessage.TypeTXT)))
	f.Add(fuzzQuery(0x0002, fuzzQuestion("srv.example.com.", dnsmessage.TypeSRV)))
	f.Add(fuzzQuery(0x0003, fuzzQuestion("https.example.com.", dnsmessage.TypeHTTPS)))
	f.Add(fuzzQuery(0x0004, fuzzQuestion("q.example.com.", dnsmessage.TypeALL)))
	// Root-zone query: a lone zero label
	f.Add(fuzzQuery(0x0005, fuzzQuestion(".", dnsmessage.TypeNS)))
	// Single-label name, as sent for localhost
	f.Add(fuzzQuery(0x0006, fuzzQuestion("localhost.", dnsmessage.TypeA)))
	// Mixed-case name so asciiLowerName's loop has work to do
	f.Add(fuzzQuery(0x1234, fuzzQuestion("MiXeD.CaSe.Example.COM.", dnsmessage.TypeA)))
	// Underscore labels, as used for SVCB/HTTPS service names and DKIM
	f.Add(fuzzQuery(0x0007, fuzzQuestion("_dns.resolver.arpa.", dnsmessage.TypeA)))
	// All-numeric labels, an IPv4-looking host name
	f.Add(fuzzQuery(0x0008, fuzzQuestion("10.0.0.1.example.com.", dnsmessage.TypePTR)))
	// 63-byte label, the per-label wire limit
	f.Add(fuzzQuery(0x0002, fuzzQuestion(fuzzMaxLabelName(), dnsmessage.TypeA)))
	// 255-byte encoded name, the whole-QNAME wire limit
	f.Add(fuzzQuery(0x0009, fuzzQuestion(fuzzMaxQName(), dnsmessage.TypeA)))
	// QTYPE A + QCLASS INET, then a trailing label "b" and a compression
	// pointer back to offset 12; the pointer sits after QCLASS and is never
	// parsed as part of the question
	f.Add(fuzzQuery(0x0003, []byte{
		1, 'a', 0x00, // label "a" at offset 12, root-terminated
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = INET
		1, 'b', // label "b" at offset 19
		0xC0, 0x0C, // pointer back to offset 12: name is "a."
	}))
	// QTYPE AAAA + QCLASS INET, then a trailing pointer to offset 16 and a
	// label "b" pointer to offset 12; the pointers sit after QCLASS
	f.Add(fuzzQuery(0x0003, []byte{
		1, 'a', 0x00, // label "a" at offset 12, root-terminated
		0x00, 0x1c, // QTYPE = AAAA
		0x00, 0x01, // QCLASS = INET
		0xC0, 0x10, // pointer to offset 16
		1, 'b', 0xC0, 0x0C, // label "b" + pointer to offset 12
	}))
	// QNAME ending in a compression pointer: label "a" at offset 12 points to
	// the "b." label at offset 20, so the name expands to "a.b.". QTYPE and
	// QCLASS are read straight after the pointer, not after the target.
	f.Add(fuzzQuery(0x000c, []byte{
		1, 'a', 0xC0, 0x14, // label "a" + pointer to offset 20
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = INET
		1, 'b', 0x00, // label "b" at offset 20, root-terminated
	}))
	// Chained compression pointers: the pointer at offset 14 lands on another
	// pointer at offset 24, which lands on "d." at offset 30; name is "a.d."
	f.Add(fuzzQuery(0x000d, []byte{
		1, 'a', 0xC0, 24, // label "a" + pointer to offset 24
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = INET
		0, 0, 0, 0, // offsets 20-23, never parsed as part of the name
		0xC0, 30, // pointer to offset 30
		0, 0, 0, 0, // offsets 26-29
		1, 'd', 0x00, // label "d" at offset 30, root-terminated
	}))
	// Truncations: header claims one question but the packet ends inside it
	full := fuzzQuery(0x000a, fuzzQuestion("truncate.example.com.", dnsmessage.TypeA))
	f.Add(full[:13]) // inside the first label
	f.Add(full[:16])
	f.Add(full[:19])
	f.Add(full[:21])
	f.Add(full[:34]) // root label included, cut before QTYPE
	f.Add(full[:35]) // inside QTYPE
	f.Add(full[:37]) // inside QCLASS
	// Empty and header-only inputs
	f.Add(make([]byte, 12))
	// Zero questions; rejected before parsing
	f.Add(fuzzQuery(0x000b, nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		getDNSQueryCacheKey(data)
	})
}

func FuzzAsciiLowerName(f *testing.F) {
	// A bare name without a 12-byte header fails p.Start and never reaches asciiLowerName
	f.Add(fuzzQuery(0x1234, fuzzQuestion("foo.com.", dnsmessage.TypeA)))
	f.Add(fuzzQuery(0x1234, fuzzQuestion("FOO.CoM.", dnsmessage.TypeA)))
	f.Add(fuzzQuery(0x1234, fuzzQuestion(fuzzMaxLabelName(), dnsmessage.TypeA)))
	f.Add(fuzzQuery(0x1234, fuzzQuestion(fuzzMaxQName(), dnsmessage.TypeA)))
	// A zero-length name
	f.Add(fuzzQuery(0x1234, fuzzQuestion(".", dnsmessage.TypeA)))
	// Punctuation adjacent to the A-Z range
	f.Add(fuzzQuery(0x1234, fuzzQuestion("@[].example.com.", dnsmessage.TypeA)))

	f.Fuzz(func(t *testing.T, data []byte) {
		var p dnsmessage.Parser
		if _, err := p.Start(data); err != nil {
			return
		}
		q, err := p.Question()
		if err != nil {
			return
		}
		_ = asciiLowerName(q.Name)
	})
}
