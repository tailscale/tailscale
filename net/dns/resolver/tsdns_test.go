// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"bytes"
	"errors"
	"net"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/tstest"
)

var testipv4 = netaddr.IPv4(1, 2, 3, 4)
var testipv6 = netaddr.IPv6Raw([16]byte{
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
})

var dnsCfg = Config{
	Hosts: map[string][]netaddr.IP{
		"test1.ipn.dev.": []netaddr.IP{testipv4},
		"test2.ipn.dev.": []netaddr.IP{testipv6},
	},
	LocalDomains: []string{"ipn.dev."},
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

type dnsResponse struct {
	ip    netaddr.IP
	name  string
	rcode dns.RCode
}

func unpackResponse(payload []byte) (dnsResponse, error) {
	var response dnsResponse
	var parser dns.Parser

	h, err := parser.Start(payload)
	if err != nil {
		return response, err
	}

	if !h.Response {
		return response, errors.New("not a response")
	}

	response.rcode = h.RCode
	if response.rcode != dns.RCodeSuccess {
		return response, nil
	}

	err = parser.SkipAllQuestions()
	if err != nil {
		return response, err
	}

	ah, err := parser.AnswerHeader()
	if err != nil {
		return response, err
	}

	switch ah.Type {
	case dns.TypeA:
		res, err := parser.AResource()
		if err != nil {
			return response, err
		}
		response.ip = netaddr.IPv4(res.A[0], res.A[1], res.A[2], res.A[3])
	case dns.TypeAAAA:
		res, err := parser.AAAAResource()
		if err != nil {
			return response, err
		}
		response.ip = netaddr.IPv6Raw(res.AAAA)
	case dns.TypeNS:
		res, err := parser.NSResource()
		if err != nil {
			return response, err
		}
		response.name = res.NS.String()
	default:
		return response, errors.New("type not in {A, AAAA, NS}")
	}

	return response, nil
}

func syncRespond(r *Resolver, query []byte) ([]byte, error) {
	r.EnqueueRequest(query, netaddr.IPPort{})
	payload, _, err := r.NextResponse()
	return payload, err
}

func mustIP(str string) netaddr.IP {
	ip, err := netaddr.ParseIP(str)
	if err != nil {
		panic(err)
	}
	return ip
}

func TestRDNSNameToIPv4(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantIP netaddr.IP
		wantOK bool
	}{
		{"valid", "4.123.24.1.in-addr.arpa.", netaddr.IPv4(1, 24, 123, 4), true},
		{"double_dot", "1..2.3.in-addr.arpa.", netaddr.IP{}, false},
		{"overflow", "1.256.3.4.in-addr.arpa.", netaddr.IP{}, false},
		{"not_ip", "sub.do.ma.in.in-addr.arpa.", netaddr.IP{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ok := rdnsNameToIPv4(tt.input)
			if ok != tt.wantOK {
				t.Errorf("ok = %v; want %v", ok, tt.wantOK)
			} else if ok && ip != tt.wantIP {
				t.Errorf("ip = %v; want %v", ip, tt.wantIP)
			}
		})
	}
}

func TestRDNSNameToIPv6(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantIP netaddr.IP
		wantOK bool
	}{
		{
			"valid",
			"b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			mustIP("2001:db8::567:89ab"),
			true,
		},
		{
			"double_dot",
			"b..9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			netaddr.IP{},
			false,
		},
		{
			"double_hex",
			"b.a.98.0.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			netaddr.IP{},
			false,
		},
		{
			"not_hex",
			"b.a.g.0.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			netaddr.IP{},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ok := rdnsNameToIPv6(tt.input)
			if ok != tt.wantOK {
				t.Errorf("ok = %v; want %v", ok, tt.wantOK)
			} else if ok && ip != tt.wantIP {
				t.Errorf("ip = %v; want %v", ip, tt.wantIP)
			}
		})
	}
}

func TestResolveLocal(t *testing.T) {
	r, err := New(t.Logf, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Close()

	r.SetConfig(dnsCfg)

	tests := []struct {
		name  string
		qname string
		qtype dns.Type
		ip    netaddr.IP
		code  dns.RCode
	}{
		{"ipv4", "test1.ipn.dev.", dns.TypeA, testipv4, dns.RCodeSuccess},
		{"ipv6", "test2.ipn.dev.", dns.TypeAAAA, testipv6, dns.RCodeSuccess},
		{"no-ipv6", "test1.ipn.dev.", dns.TypeAAAA, netaddr.IP{}, dns.RCodeSuccess},
		{"nxdomain", "test3.ipn.dev.", dns.TypeA, netaddr.IP{}, dns.RCodeNameError},
		{"foreign domain", "google.com.", dns.TypeA, netaddr.IP{}, dns.RCodeRefused},
		{"all", "test1.ipn.dev.", dns.TypeA, testipv4, dns.RCodeSuccess},
		{"mx-ipv4", "test1.ipn.dev.", dns.TypeMX, netaddr.IP{}, dns.RCodeSuccess},
		{"mx-ipv6", "test2.ipn.dev.", dns.TypeMX, netaddr.IP{}, dns.RCodeSuccess},
		{"mx-nxdomain", "test3.ipn.dev.", dns.TypeMX, netaddr.IP{}, dns.RCodeNameError},
		{"ns-nxdomain", "test3.ipn.dev.", dns.TypeNS, netaddr.IP{}, dns.RCodeNameError},
		{"onion-domain", "footest.onion.", dns.TypeA, netaddr.IP{}, dns.RCodeNameError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, code := r.resolveLocal(tt.qname, tt.qtype)
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

func TestResolveLocalReverse(t *testing.T) {
	r, err := New(t.Logf, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Close()

	r.SetConfig(dnsCfg)

	tests := []struct {
		name string
		ip   netaddr.IP
		want string
		code dns.RCode
	}{
		{"ipv4", testipv4, "test1.ipn.dev.", dns.RCodeSuccess},
		{"ipv6", testipv6, "test2.ipn.dev.", dns.RCodeSuccess},
		{"nxdomain", netaddr.IPv4(4, 3, 2, 1), "", dns.RCodeNameError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, code := r.resolveLocalReverse(tt.ip)
			if code != tt.code {
				t.Errorf("code = %v; want %v", code, tt.code)
			}
			if name != tt.want {
				t.Errorf("ip = %v; want %v", name, tt.want)
			}
		})
	}
}

func ipv6Works() bool {
	c, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func TestDelegate(t *testing.T) {
	tstest.ResourceCheck(t)

	if !ipv6Works() {
		t.Skip("skipping test that requires localhost IPv6")
	}

	dnsHandleFunc("test.site.", resolveToIP(testipv4, testipv6, "dns.test.site."))
	dnsHandleFunc("nxdomain.site.", resolveToNXDOMAIN)

	v4server, v4errch := serveDNS(t, "127.0.0.1:0")
	v6server, v6errch := serveDNS(t, "[::1]:0")

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

	r, err := New(t.Logf, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Close()

	cfg := dnsCfg
	cfg.Routes = map[string][]netaddr.IPPort{
		".": {
			netaddr.MustParseIPPort(v4server.PacketConn.LocalAddr().String()),
			netaddr.MustParseIPPort(v6server.PacketConn.LocalAddr().String()),
		},
	}
	r.SetConfig(cfg)

	tests := []struct {
		title    string
		query    []byte
		response dnsResponse
	}{
		{
			"ipv4",
			dnspacket("test.site.", dns.TypeA),
			dnsResponse{ip: testipv4, rcode: dns.RCodeSuccess},
		},
		{
			"ipv6",
			dnspacket("test.site.", dns.TypeAAAA),
			dnsResponse{ip: testipv6, rcode: dns.RCodeSuccess},
		},
		{
			"ns",
			dnspacket("test.site.", dns.TypeNS),
			dnsResponse{name: "dns.test.site.", rcode: dns.RCodeSuccess},
		},
		{
			"nxdomain",
			dnspacket("nxdomain.site.", dns.TypeA),
			dnsResponse{rcode: dns.RCodeNameError},
		},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			payload, err := syncRespond(r, tt.query)
			if err != nil {
				t.Errorf("err = %v; want nil", err)
				return
			}
			response, err := unpackResponse(payload)
			if err != nil {
				t.Errorf("extract: err = %v; want nil (in %x)", err, payload)
				return
			}
			if response.rcode != tt.response.rcode {
				t.Errorf("rcode = %v; want %v", response.rcode, tt.response.rcode)
			}
			if response.ip != tt.response.ip {
				t.Errorf("ip = %v; want %v", response.ip, tt.response.ip)
			}
			if response.name != tt.response.name {
				t.Errorf("name = %v; want %v", response.name, tt.response.name)
			}
		})
	}
}

func TestDelegateCollision(t *testing.T) {
	dnsHandleFunc("test.site.", resolveToIP(testipv4, testipv6, "dns.test.site."))

	server, errch := serveDNS(t, "127.0.0.1:0")
	defer func() {
		if err := <-errch; err != nil {
			t.Errorf("server error: %v", err)
		}
	}()

	if server == nil {
		return
	}
	defer server.Shutdown()

	r, err := New(t.Logf, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Close()

	cfg := dnsCfg
	cfg.Routes = map[string][]netaddr.IPPort{
		".": {
			netaddr.MustParseIPPort(server.PacketConn.LocalAddr().String()),
		},
	}
	r.SetConfig(cfg)

	packets := []struct {
		qname string
		qtype dns.Type
		addr  netaddr.IPPort
	}{
		{"test.site.", dns.TypeA, netaddr.IPPort{IP: netaddr.IPv4(1, 1, 1, 1), Port: 1001}},
		{"test.site.", dns.TypeAAAA, netaddr.IPPort{IP: netaddr.IPv4(1, 1, 1, 1), Port: 1002}},
	}

	// packets will have the same dns txid.
	for _, p := range packets {
		payload := dnspacket(p.qname, p.qtype)
		err := r.EnqueueRequest(payload, p.addr)
		if err != nil {
			t.Error(err)
		}
	}

	// Despite the txid collision, the answer(s) should still match the query.
	resp, addr, err := r.NextResponse()
	if err != nil {
		t.Error(err)
	}

	var p dns.Parser
	_, err = p.Start(resp)
	if err != nil {
		t.Error(err)
	}
	err = p.SkipAllQuestions()
	if err != nil {
		t.Error(err)
	}
	ans, err := p.AllAnswers()
	if err != nil {
		t.Error(err)
	}

	var wantType dns.Type
	switch ans[0].Body.(type) {
	case *dns.AResource:
		wantType = dns.TypeA
	case *dns.AAAAResource:
		wantType = dns.TypeAAAA
	default:
		t.Errorf("unexpected answer type: %T", ans[0].Body)
	}

	for _, p := range packets {
		if p.qtype == wantType && p.addr != addr {
			t.Errorf("addr = %v; want %v", addr, p.addr)
		}
	}
}

var allResponse = []byte{
	0x00, 0x00, // transaction id: 0
	0x84, 0x00, // flags: response, authoritative, no error
	0x00, 0x01, // one question
	0x00, 0x01, // one answer
	0x00, 0x00, 0x00, 0x00, // no authority or additional RRs
	// Question:
	0x05, 0x74, 0x65, 0x73, 0x74, 0x31, 0x03, 0x69, 0x70, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00, // name
	0x00, 0xff, 0x00, 0x01, // type ALL, class IN
	// Answer:
	0x05, 0x74, 0x65, 0x73, 0x74, 0x31, 0x03, 0x69, 0x70, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00, // name
	0x00, 0x01, 0x00, 0x01, // type A, class IN
	0x00, 0x00, 0x02, 0x58, // TTL: 600
	0x00, 0x04, // length: 4 bytes
	0x01, 0x02, 0x03, 0x04, // A: 1.2.3.4
}

var ipv4Response = []byte{
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

var ipv6Response = []byte{
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

var ipv4UppercaseResponse = []byte{
	0x00, 0x00, // transaction id: 0
	0x84, 0x00, // flags: response, authoritative, no error
	0x00, 0x01, // one question
	0x00, 0x01, // one answer
	0x00, 0x00, 0x00, 0x00, // no authority or additional RRs
	// Question:
	0x05, 0x54, 0x45, 0x53, 0x54, 0x31, 0x03, 0x49, 0x50, 0x4e, 0x03, 0x44, 0x45, 0x56, 0x00, // name
	0x00, 0x01, 0x00, 0x01, // type A, class IN
	// Answer:
	0x05, 0x54, 0x45, 0x53, 0x54, 0x31, 0x03, 0x49, 0x50, 0x4e, 0x03, 0x44, 0x45, 0x56, 0x00, // name
	0x00, 0x01, 0x00, 0x01, // type A, class IN
	0x00, 0x00, 0x02, 0x58, // TTL: 600
	0x00, 0x04, // length: 4 bytes
	0x01, 0x02, 0x03, 0x04, // A: 1.2.3.4
}

var ptrResponse = []byte{
	0x00, 0x00, // transaction id: 0
	0x84, 0x00, // flags: response, authoritative, no error
	0x00, 0x01, // one question
	0x00, 0x01, // one answer
	0x00, 0x00, 0x00, 0x00, // no authority or additional RRs
	// Question: 4.3.2.1.in-addr.arpa
	0x01, 0x34, 0x01, 0x33, 0x01, 0x32, 0x01, 0x31, 0x07,
	0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00,
	0x00, 0x0c, 0x00, 0x01, // type PTR, class IN
	// Answer: 4.3.2.1.in-addr.arpa
	0x01, 0x34, 0x01, 0x33, 0x01, 0x32, 0x01, 0x31, 0x07,
	0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00,
	0x00, 0x0c, 0x00, 0x01, // type PTR, class IN
	0x00, 0x00, 0x02, 0x58, // TTL: 600
	0x00, 0x0f, // length: 15 bytes
	// PTR: test1.ipn.dev
	0x05, 0x74, 0x65, 0x73, 0x74, 0x31, 0x03, 0x69, 0x70, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00,
}

var ptrResponse6 = []byte{
	0x00, 0x00, // transaction id: 0
	0x84, 0x00, // flags: response, authoritative, no error
	0x00, 0x01, // one question
	0x00, 0x01, // one answer
	0x00, 0x00, 0x00, 0x00, // no authority or additional RRs
	// Question: f.0.e.0.d.0.c.0.b.0.a.0.9.0.8.0.7.0.6.0.5.0.4.0.3.0.2.0.1.0.0.0.ip6.arpa
	0x01, 0x66, 0x01, 0x30, 0x01, 0x65, 0x01, 0x30,
	0x01, 0x64, 0x01, 0x30, 0x01, 0x63, 0x01, 0x30,
	0x01, 0x62, 0x01, 0x30, 0x01, 0x61, 0x01, 0x30,
	0x01, 0x39, 0x01, 0x30, 0x01, 0x38, 0x01, 0x30,
	0x01, 0x37, 0x01, 0x30, 0x01, 0x36, 0x01, 0x30,
	0x01, 0x35, 0x01, 0x30, 0x01, 0x34, 0x01, 0x30,
	0x01, 0x33, 0x01, 0x30, 0x01, 0x32, 0x01, 0x30,
	0x01, 0x31, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30,
	0x03, 0x69, 0x70, 0x36,
	0x04, 0x61, 0x72, 0x70, 0x61, 0x00,
	0x00, 0x0c, 0x00, 0x01, // type PTR, class IN6
	// Answer: f.0.e.0.d.0.c.0.b.0.a.0.9.0.8.0.7.0.6.0.5.0.4.0.3.0.2.0.1.0.0.0.ip6.arpa
	0x01, 0x66, 0x01, 0x30, 0x01, 0x65, 0x01, 0x30,
	0x01, 0x64, 0x01, 0x30, 0x01, 0x63, 0x01, 0x30,
	0x01, 0x62, 0x01, 0x30, 0x01, 0x61, 0x01, 0x30,
	0x01, 0x39, 0x01, 0x30, 0x01, 0x38, 0x01, 0x30,
	0x01, 0x37, 0x01, 0x30, 0x01, 0x36, 0x01, 0x30,
	0x01, 0x35, 0x01, 0x30, 0x01, 0x34, 0x01, 0x30,
	0x01, 0x33, 0x01, 0x30, 0x01, 0x32, 0x01, 0x30,
	0x01, 0x31, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30,
	0x03, 0x69, 0x70, 0x36,
	0x04, 0x61, 0x72, 0x70, 0x61, 0x00,
	0x00, 0x0c, 0x00, 0x01, // type PTR, class IN
	0x00, 0x00, 0x02, 0x58, // TTL: 600
	0x00, 0x0f, // length: 15 bytes
	// PTR: test2.ipn.dev
	0x05, 0x74, 0x65, 0x73, 0x74, 0x32, 0x03, 0x69, 0x70, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00,
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

var emptyResponse = []byte{
	0x00, 0x00, // transaction id: 0
	0x84, 0x00, // flags: response, authoritative, no error
	0x00, 0x01, // one question
	0x00, 0x00, // no answers
	0x00, 0x00, 0x00, 0x00, // no authority or additional RRs
	// Question:
	0x05, 0x74, 0x65, 0x73, 0x74, 0x31, 0x03, 0x69, 0x70, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00, // name
	0x00, 0x1c, 0x00, 0x01, // type AAAA, class IN
}

func TestFull(t *testing.T) {
	r, err := New(t.Logf, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Close()

	r.SetConfig(dnsCfg)

	// One full packet and one error packet
	tests := []struct {
		name     string
		request  []byte
		response []byte
	}{
		{"all", dnspacket("test1.ipn.dev.", dns.TypeALL), allResponse},
		{"ipv4", dnspacket("test1.ipn.dev.", dns.TypeA), ipv4Response},
		{"ipv6", dnspacket("test2.ipn.dev.", dns.TypeAAAA), ipv6Response},
		{"no-ipv6", dnspacket("test1.ipn.dev.", dns.TypeAAAA), emptyResponse},
		{"upper", dnspacket("TEST1.IPN.DEV.", dns.TypeA), ipv4UppercaseResponse},
		{"ptr", dnspacket("4.3.2.1.in-addr.arpa.", dns.TypePTR), ptrResponse},
		{"ptr", dnspacket("f.0.e.0.d.0.c.0.b.0.a.0.9.0.8.0.7.0.6.0.5.0.4.0.3.0.2.0.1.0.0.0.ip6.arpa.",
			dns.TypePTR), ptrResponse6},
		{"nxdomain", dnspacket("test3.ipn.dev.", dns.TypeA), nxdomainResponse},
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
	r, err := New(t.Logf, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Close()
	r.SetConfig(dnsCfg)

	// It is seemingly pointless to test allocs in the delegate path,
	// as dialer.Dial -> Read -> Write alone comprise 12 allocs.
	tests := []struct {
		name  string
		query []byte
		want  int
	}{
		// Name lowercasing and response slice created by dns.NewBuilder.
		{"forward", dnspacket("test1.ipn.dev.", dns.TypeA), 2},
		// 3 extra allocs in rdnsNameToIPv4 and one in marshalPTRRecord (dns.NewName).
		{"reverse", dnspacket("4.3.2.1.in-addr.arpa.", dns.TypePTR), 5},
	}

	for _, tt := range tests {
		allocs := testing.AllocsPerRun(100, func() {
			syncRespond(r, tt.query)
		})
		if int(allocs) > tt.want {
			t.Errorf("%s: allocs = %v; want %v", tt.name, allocs, tt.want)
		}
	}
}

func TestTrimRDNSBonjourPrefix(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"b._dns-sd._udp.0.10.20.172.in-addr.arpa.", true},
		{"db._dns-sd._udp.0.10.20.172.in-addr.arpa.", true},
		{"r._dns-sd._udp.0.10.20.172.in-addr.arpa.", true},
		{"dr._dns-sd._udp.0.10.20.172.in-addr.arpa.", true},
		{"lb._dns-sd._udp.0.10.20.172.in-addr.arpa.", true},
		{"qq._dns-sd._udp.0.10.20.172.in-addr.arpa.", false},
		{"0.10.20.172.in-addr.arpa.", false},
		{"i-have-no-dot", false},
	}

	for _, test := range tests {
		got := hasRDNSBonjourPrefix(test.in)
		if got != test.want {
			t.Errorf("trimRDNSBonjourPrefix(%q) = %v, want %v", test.in, got, test.want)
		}
	}
}

func BenchmarkFull(b *testing.B) {
	dnsHandleFunc("test.site.", resolveToIP(testipv4, testipv6, "dns.test.site."))

	server, errch := serveDNS(b, "127.0.0.1:0")
	defer func() {
		if err := <-errch; err != nil {
			b.Errorf("server error: %v", err)
		}
	}()

	if server == nil {
		return
	}
	defer server.Shutdown()

	r, err := New(b.Logf, nil)
	if err != nil {
		b.Fatalf("start: %v", err)
	}
	defer r.Close()

	cfg := dnsCfg
	cfg.Routes = map[string][]netaddr.IPPort{
		".": {
			netaddr.MustParseIPPort(server.PacketConn.LocalAddr().String()),
		},
	}

	tests := []struct {
		name    string
		request []byte
	}{
		{"forward", dnspacket("test1.ipn.dev.", dns.TypeA)},
		{"reverse", dnspacket("4.3.2.1.in-addr.arpa.", dns.TypePTR)},
		{"delegated", dnspacket("test.site.", dns.TypeA)},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				syncRespond(r, tt.request)
			}
		})
	}
}

func TestMarshalResponseFormatError(t *testing.T) {
	resp := new(response)
	resp.Header.RCode = dns.RCodeFormatError
	v, err := marshalResponse(resp)
	if err != nil {
		t.Errorf("marshal error: %v", err)
	}
	t.Logf("response: %q", v)
}
