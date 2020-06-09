// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdns

import (
	"bytes"
	"sync"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/wgengine/packet"
)

var dnsMap = &Map{
	domainToIP: map[string]netaddr.IP{
		"test1.ipn.dev": netaddr.IPv4(1, 2, 3, 4),
		"test2.ipn.dev": netaddr.IPv4(5, 6, 7, 8),
	},
}

func dnspacket(srcip, dstip packet.IP, domain string, tp dns.Type, response bool) *packet.ParsedPacket {
	dnsHeader := dns.Header{Response: response}
	question := dns.Question{
		Name:  dns.MustNewName(domain),
		Type:  tp,
		Class: dns.ClassINET,
	}
	udpHeader := &packet.UDPHeader{
		IPHeader: packet.IPHeader{
			SrcIP:   srcip,
			DstIP:   dstip,
			IPProto: packet.UDP,
		},
		SrcPort: 1234,
		DstPort: 53,
	}

	builder := dns.NewBuilder(nil, dnsHeader)
	builder.StartQuestions()
	builder.Question(question)
	payload, _ := builder.Finish()

	buf := packet.Generate(udpHeader, payload)

	pp := new(packet.ParsedPacket)
	pp.Decode(buf)

	return pp
}

func TestAcceptsPacket(t *testing.T) {
	r := NewResolver(t.Logf)
	r.SetMap(dnsMap)

	src := packet.IP(0x64656667) // 100.101.102.103
	dst := packet.IP(0x64646464) // 100.100.100.100
	tests := []struct {
		name    string
		request *packet.ParsedPacket
		want    bool
	}{
		{"valid", dnspacket(src, dst, "test1.ipn.dev.", dns.TypeA, false), true},
		{"invalid", dnspacket(dst, src, "test1.ipn.dev.", dns.TypeA, false), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accepts := r.AcceptsPacket(tt.request)
			if accepts != tt.want {
				t.Errorf("accepts = %v; want %v", accepts, tt.want)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	r := NewResolver(t.Logf)
	r.SetMap(dnsMap)

	tests := []struct {
		name   string
		domain string
		ip     netaddr.IP
		code   dns.RCode
		iserr  bool
	}{
		{"valid", "test1.ipn.dev", netaddr.IPv4(1, 2, 3, 4), dns.RCodeSuccess, false},
		{"nxdomain", "test3.ipn.dev", netaddr.IP{}, dns.RCodeNameError, true},
		{"not our domain", "google.com", netaddr.IP{}, dns.RCodeRefused, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, code, err := r.Resolve(tt.domain)
			if err != nil && !tt.iserr {
				t.Errorf("err = %v; want nil", err)
			} else if err == nil && tt.iserr {
				t.Errorf("err = nil; want non-nil")
			}
			if code != tt.code {
				t.Errorf("code = %v; want %v", code, tt.code)
			}
			// Only check ip for non-err
			if !tt.iserr && ip != tt.ip {
				t.Errorf("ip = %v; want %v", ip, tt.ip)
			}
		})
	}
}

func TestConcurrentSet(t *testing.T) {
	r := NewResolver(t.Logf)

	// This is purely to ensure that Resolve does not race with SetMap.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.SetMap(dnsMap)
	}()
	go func() {
		defer wg.Done()
		r.Resolve("test1.ipn.dev")
	}()
	wg.Wait()
}

var validResponse = []byte{
	// IP header
	0x45, 0x00, 0x00, 0x58, 0xff, 0xff, 0x00, 0x00, 0x40, 0x11, 0xe7, 0x00,
	// Source IP
	0x64, 0x64, 0x64, 0x64,
	// Destination IP
	0x64, 0x65, 0x66, 0x67,
	// UDP header
	0x00, 0x35, 0x04, 0xd2, 0x00, 0x44, 0x53, 0xdd,
	// DNS payload
	0x00, 0x00, // transaction id: 0
	0x84, 0x00, // flags: response, authoritative, no error
	0x00, 0x01, // one question
	0x00, 0x01, // one answer
	0x00, 0x00, 0x00, 0x00, // no authority or additional RRs
	// Question:
	0x05, 0x74, 0x65, 0x73, 0x74, 0x31, 0x03, 0x69, 0x70, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00, // name
	0x00, 0x01, 0x00, 0x01, // type A, class IN
	// Answer:
	0x05, 0x74, 0x65, 0x73, 0x74, 0x31, 0x03, 0x69, 0x70, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00, // name
	0x00, 0x01, 0x00, 0x01, // type A, class IN
	0x00, 0x00, 0x02, 0x58, // TTL: 600
	0x00, 0x04, // length: 4 bytes
	0x01, 0x02, 0x03, 0x04, // A: 1.2.3.4
}

var nxdomainResponse = []byte{
	// IP header
	0x45, 0x00, 0x00, 0x3b, 0xff, 0xff, 0x00, 0x00, 0x40, 0x11, 0xe7, 0x1d,
	// Source IP
	0x64, 0x64, 0x64, 0x64,
	// Destination IP
	0x64, 0x65, 0x66, 0x67,
	// UDP header
	0x00, 0x35, 0x04, 0xd2, 0x00, 0x27, 0x25, 0x33,
	// DNS payload
	0x00, 0x00, // transaction id: 0
	0x84, 0x03, // flags: response, authoritative, error: nxdomain
	0x00, 0x01, // one question
	0x00, 0x00, // no answers
	0x00, 0x00, 0x00, 0x00, // no authority or additional RRs
	// Question:
	0x05, 0x74, 0x65, 0x73, 0x74, 0x33, 0x03, 0x69, 0x70, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00, // name
	0x00, 0x01, 0x00, 0x01, // type A, class IN
}

func TestFull(t *testing.T) {
	r := NewResolver(t.Logf)
	r.SetMap(dnsMap)

	src := packet.IP(0x64656667) // 100.101.102.103
	dst := packet.IP(0x64646464) // 100.100.100.100
	// One full packet and one error packet
	tests := []struct {
		name     string
		request  *packet.ParsedPacket
		response []byte
	}{
		{"valid", dnspacket(src, dst, "test1.ipn.dev.", dns.TypeA, false), validResponse},
		{"error", dnspacket(src, dst, "test3.ipn.dev.", dns.TypeA, false), nxdomainResponse},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 512)
			response, err := r.Respond(tt.request, buf)
			if err != nil {
				t.Errorf("err = %v; want nil", err)
			}
			if !bytes.Equal(response, tt.response) {
				t.Errorf("response = %x; want %x", response, tt.response)
			}
		})
	}
}

func TestAllocs(t *testing.T) {
	r := NewResolver(t.Logf)
	r.SetMap(dnsMap)

	src := packet.IP(0x64656667) // 100.101.102.103
	dst := packet.IP(0x64646464) // 100.100.100.100
	query := dnspacket(src, dst, "test1.ipn.dev.", dns.TypeA, false)

	buf := make([]byte, 512)
	allocs := testing.AllocsPerRun(100, func() {
		r.Respond(query, buf)
	})

	if allocs > 0 {
		t.Errorf("allocs = %v; want 0", allocs)
	}
}

func BenchmarkFull(b *testing.B) {
	r := NewResolver(b.Logf)
	r.SetMap(dnsMap)

	src := packet.IP(0x64656667) // 100.101.102.103
	dst := packet.IP(0x64646464) // 100.100.100.100
	// One full packet and one error packet
	tests := []struct {
		name    string
		request *packet.ParsedPacket
	}{
		{"valid", dnspacket(src, dst, "test1.ipn.dev.", dns.TypeA, false)},
		{"nxdomain", dnspacket(src, dst, "test3.ipn.dev.", dns.TypeA, false)},
	}

	buf := make([]byte, 512)
	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				r.Respond(tt.request, buf)
			}
		})
	}
}
