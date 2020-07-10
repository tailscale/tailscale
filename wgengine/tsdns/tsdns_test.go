// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdns

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
)

var testipv4 = netaddr.IPv4(1, 2, 3, 4)
var testipv6 = netaddr.IPv6Raw([16]byte{
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
})

var dnsMap = &Map{
	domainToIP: map[string]netaddr.IP{
		"test1.ipn.dev": testipv4,
		"test2.ipn.dev": testipv6,
	},
}

func dnspacket(domain string, tp dns.Type) []byte {
	var dnsHeader dns.Header
	question := dns.Question{
		Name:  dns.MustNewName(domain),
		Type:  tp,
		Class: dns.ClassINET,
	}

	builder := dns.NewBuilder(nil, dnsHeader)
	builder.StartQuestions()
	builder.Question(question)
	payload, _ := builder.Finish()

	return payload
}

func extractipcode(response []byte) (netaddr.IP, dns.RCode, error) {
	var ip netaddr.IP
	var parser dns.Parser

	h, err := parser.Start(response)
	if err != nil {
		return ip, 0, err
	}

	if !h.Response {
		return ip, 0, errors.New("not a response")
	}
	if h.RCode != dns.RCodeSuccess {
		return ip, h.RCode, nil
	}

	err = parser.SkipAllQuestions()
	if err != nil {
		return ip, 0, err
	}

	ah, err := parser.AnswerHeader()
	if err != nil {
		return ip, 0, err
	}
	switch ah.Type {
	case dns.TypeA:
		res, err := parser.AResource()
		if err != nil {
			return ip, 0, err
		}
		ip = netaddr.IPv4(res.A[0], res.A[1], res.A[2], res.A[3])
	case dns.TypeAAAA:
		res, err := parser.AAAAResource()
		if err != nil {
			return ip, 0, err
		}
		ip = netaddr.IPv6Raw(res.AAAA)
	default:
		return ip, 0, errors.New("type not in {A, AAAA}")
	}

	return ip, h.RCode, nil
}

func syncRespond(r *Resolver, query []byte) ([]byte, error) {
	request := Packet{Payload: query}
	r.EnqueueRequest(request)
	resp, err := r.NextResponse()
	return resp.Payload, err
}

func TestResolve(t *testing.T) {
	r := NewResolver(t.Logf, "ipn.dev")
	r.SetMap(dnsMap)
	r.Start()

	tests := []struct {
		name   string
		domain string
		ip     netaddr.IP
		code   dns.RCode
	}{
		{"ipv4", "test1.ipn.dev", testipv4, dns.RCodeSuccess},
		{"ipv6", "test2.ipn.dev", testipv6, dns.RCodeSuccess},
		{"nxdomain", "test3.ipn.dev", netaddr.IP{}, dns.RCodeNameError},
		{"foreign domain", "google.com", netaddr.IP{}, dns.RCodeNameError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, code, err := r.Resolve(tt.domain)
			if err != nil {
				t.Errorf("err = %v; want nil", err)
			}
			if code != tt.code {
				t.Errorf("code = %v; want %v", code, tt.code)
			}
			// Only check ip for non-err
			if ip != tt.ip {
				t.Errorf("ip = %v; want %v", ip, tt.ip)
			}
		})
	}
}

func TestDelegate(t *testing.T) {
	dnsHandleFunc("test.site.", resolveToIP(testipv4, testipv6))
	dnsHandleFunc("nxdomain.site.", resolveToNXDOMAIN)

	v4server, v4errch := serveDNS("127.0.0.1:0")
	v6server, v6errch := serveDNS("[::1]:0")

	defer func() {
		if err := <-v4errch; err != nil {
			t.Errorf("v4 server error: %v", err)
		}
		if err := <-v6errch; err != nil {
			t.Errorf("v6 server error: %v", err)
		}
	}()
	if v4server != nil {
		defer v4server.Shutdown()
	}
	if v6server != nil {
		defer v6server.Shutdown()
	}

	if v4server == nil || v6server == nil {
		// There is an error in at least one of the channels
		// and we cannot proceed; return to see it.
		return
	}

	r := NewResolver(t.Logf, "ipn.dev")
	r.SetNameservers([]string{
		v4server.PacketConn.LocalAddr().String(),
		v6server.PacketConn.LocalAddr().String(),
	})
	r.Start()

	tests := []struct {
		name  string
		query []byte
		ip    netaddr.IP
		code  dns.RCode
	}{
		{"ipv4", dnspacket("test.site.", dns.TypeA), testipv4, dns.RCodeSuccess},
		{"ipv6", dnspacket("test.site.", dns.TypeAAAA), testipv6, dns.RCodeSuccess},
		{"nxdomain", dnspacket("nxdomain.site.", dns.TypeA), netaddr.IP{}, dns.RCodeNameError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := syncRespond(r, tt.query)
			if err != nil {
				t.Errorf("err = %v; want nil", err)
				return
			}
			ip, code, err := extractipcode(resp)
			if err != nil {
				t.Errorf("extract: err = %v; want nil (in %x)", err, resp)
				return
			}
			if code != tt.code {
				t.Errorf("code = %v; want %v", code, tt.code)
			}
			if ip != tt.ip {
				t.Errorf("ip = %v; want %v", ip, tt.ip)
			}
		})
	}
}

func TestConcurrentSetMap(t *testing.T) {
	r := NewResolver(t.Logf, "ipn.dev")
	r.Start()

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

func TestConcurrentSetNameservers(t *testing.T) {
	r := NewResolver(t.Logf, "ipn.dev")
	r.Start()
	packet := dnspacket("google.com.", dns.TypeA)

	// This is purely to ensure that delegation does not race with SetNameservers.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.SetNameservers([]string{"9.9.9.9:53"})
	}()
	go func() {
		defer wg.Done()
		syncRespond(r, packet)
	}()
	wg.Wait()
}

var validIPv4Response = []byte{
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

var validIPv6Response = []byte{
	0x00, 0x00, // transaction id: 0
	0x84, 0x00, // flags: response, authoritative, no error
	0x00, 0x01, // one question
	0x00, 0x01, // one answer
	0x00, 0x00, 0x00, 0x00, // no authority or additional RRs
	// Question:
	0x05, 0x74, 0x65, 0x73, 0x74, 0x32, 0x03, 0x69, 0x70, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00, // name
	0x00, 0x1c, 0x00, 0x01, // type AAAA, class IN
	// Answer:
	0x05, 0x74, 0x65, 0x73, 0x74, 0x32, 0x03, 0x69, 0x70, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00, // name
	0x00, 0x1c, 0x00, 0x01, // type AAAA, class IN
	0x00, 0x00, 0x02, 0x58, // TTL: 600
	0x00, 0x10, // length: 16 bytes
	// AAAA: 0001:0203:0405:0607:0809:0A0B:0C0D:0E0F
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0xb, 0xc, 0xd, 0xe, 0xf,
}

var nxdomainResponse = []byte{
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
	r := NewResolver(t.Logf, "ipn.dev")
	r.SetMap(dnsMap)
	r.Start()

	// One full packet and one error packet
	tests := []struct {
		name     string
		request  []byte
		response []byte
	}{
		{"ipv4", dnspacket("test1.ipn.dev.", dns.TypeA), validIPv4Response},
		{"ipv6", dnspacket("test2.ipn.dev.", dns.TypeAAAA), validIPv6Response},
		{"error", dnspacket("test3.ipn.dev.", dns.TypeA), nxdomainResponse},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := syncRespond(r, tt.request)
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
	r := NewResolver(t.Logf, "ipn.dev")
	r.SetMap(dnsMap)
	r.Start()

	// It is seemingly pointless to test allocs in the delegate path,
	// as dialer.Dial -> Read -> Write alone comprise 12 allocs.
	query := dnspacket("test1.ipn.dev.", dns.TypeA)

	allocs := testing.AllocsPerRun(100, func() {
		syncRespond(r, query)
	})

	if allocs > 1 {
		t.Errorf("allocs = %v; want 1", allocs)
	}
}

func BenchmarkFull(b *testing.B) {
	r := NewResolver(b.Logf, "ipn.dev")
	r.SetMap(dnsMap)
	r.Start()

	// One full packet and one error packet
	tests := []struct {
		name    string
		request []byte
	}{
		{"valid", dnspacket("test1.ipn.dev.", dns.TypeA)},
		{"nxdomain", dnspacket("test3.ipn.dev.", dns.TypeA)},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				syncRespond(r, tt.request)
			}
		})
	}
}
