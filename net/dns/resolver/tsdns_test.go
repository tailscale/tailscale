// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/tstest"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/monitor"
)

var testipv4 = netaddr.MustParseIP("1.2.3.4")
var testipv6 = netaddr.MustParseIP("0001:0203:0405:0607:0809:0a0b:0c0d:0e0f")

var dnsCfg = Config{
	Hosts: map[dnsname.FQDN][]netaddr.IP{
		"test1.ipn.dev.": []netaddr.IP{testipv4},
		"test2.ipn.dev.": []netaddr.IP{testipv6},
	},
	LocalDomains: []dnsname.FQDN{"ipn.dev."},
}

const noEdns = 0

func dnspacket(domain dnsname.FQDN, tp dns.Type, ednsSize uint16) []byte {
	var dnsHeader dns.Header
	question := dns.Question{
		Name:  dns.MustNewName(domain.WithTrailingDot()),
		Type:  tp,
		Class: dns.ClassINET,
	}

	builder := dns.NewBuilder(nil, dnsHeader)
	if err := builder.StartQuestions(); err != nil {
		panic(err)
	}
	if err := builder.Question(question); err != nil {
		panic(err)
	}

	if ednsSize != noEdns {
		if err := builder.StartAdditionals(); err != nil {
			panic(err)
		}

		ednsHeader := dns.ResourceHeader{
			Name:  dns.MustNewName("."),
			Type:  dns.TypeOPT,
			Class: dns.Class(ednsSize),
		}

		if err := builder.OPTResource(ednsHeader, dns.OPTResource{}); err != nil {
			panic(err)
		}
	}

	payload, _ := builder.Finish()

	return payload
}

type dnsResponse struct {
	ip               netaddr.IP
	txt              []string
	name             dnsname.FQDN
	rcode            dns.RCode
	truncated        bool
	requestEdns      bool
	requestEdnsSize  uint16
	responseEdns     bool
	responseEdnsSize uint16
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

	response.truncated = h.Truncated
	if response.truncated {
		// TODO(#2067): Ideally, answer processing should still succeed when
		// dealing with a truncated message, but currently when we truncate
		// a packet, it's caused by the buffer being too small and usually that
		// means the data runs out mid-record. dns.Parser does not like it when
		// that happens. We can improve this by trimming off incomplete records.
		return response, nil
	}

	err = parser.SkipAllQuestions()
	if err != nil {
		return response, err
	}

	for {
		ah, err := parser.AnswerHeader()
		if err == dns.ErrSectionDone {
			break
		}
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
		case dns.TypeTXT:
			res, err := parser.TXTResource()
			if err != nil {
				return response, err
			}
			response.txt = res.TXT
		case dns.TypeNS:
			res, err := parser.NSResource()
			if err != nil {
				return response, err
			}
			response.name, err = dnsname.ToFQDN(res.NS.String())
			if err != nil {
				return response, err
			}
		default:
			return response, errors.New("type not in {A, AAAA, NS}")
		}
	}

	err = parser.SkipAllAuthorities()
	if err != nil {
		return response, err
	}

	for {
		ah, err := parser.AdditionalHeader()
		if err == dns.ErrSectionDone {
			break
		}
		if err != nil {
			return response, err
		}

		switch ah.Type {
		case dns.TypeOPT:
			_, err := parser.OPTResource()
			if err != nil {
				return response, err
			}
			response.responseEdns = true
			response.responseEdnsSize = uint16(ah.Class)
		case dns.TypeTXT:
			res, err := parser.TXTResource()
			if err != nil {
				return response, err
			}
			switch ah.Name.String() {
			case "query-info.test.":
				for _, msg := range res.TXT {
					s := strings.SplitN(msg, "=", 2)
					if len(s) != 2 {
						continue
					}
					switch s[0] {
					case "EDNS":
						response.requestEdns, err = strconv.ParseBool(s[1])
						if err != nil {
							return response, err
						}
					case "maxSize":
						sz, err := strconv.ParseUint(s[1], 10, 16)
						if err != nil {
							return response, err
						}
						response.requestEdnsSize = uint16(sz)
					}
				}
			}
		}
	}

	return response, nil
}

func syncRespond(r *Resolver, query []byte) ([]byte, error) {
	if err := r.EnqueueRequest(query, netaddr.IPPort{}); err != nil {
		return nil, fmt.Errorf("EnqueueRequest: %w", err)
	}
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
		input  dnsname.FQDN
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
		input  dnsname.FQDN
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

func newResolver(t testing.TB) *Resolver {
	return New(t.Logf, nil /* no link monitor */, nil /* no link selector */)
}

func TestResolveLocal(t *testing.T) {
	r := newResolver(t)
	defer r.Close()

	r.SetConfig(dnsCfg)

	tests := []struct {
		name  string
		qname dnsname.FQDN
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
	r := newResolver(t)
	defer r.Close()

	r.SetConfig(dnsCfg)

	tests := []struct {
		name string
		ip   netaddr.IP
		want dnsname.FQDN
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

func generateTXT(size int, source rand.Source) []string {
	const sizePerTXT = 120

	if size%2 != 0 {
		panic("even lengths only")
	}

	rng := rand.New(source)

	txts := make([]string, 0, size/sizePerTXT+1)

	raw := make([]byte, sizePerTXT/2)

	rem := size
	for ; rem > sizePerTXT; rem -= sizePerTXT {
		rng.Read(raw)
		txts = append(txts, hex.EncodeToString(raw))
	}
	if rem > 0 {
		rng.Read(raw[:rem/2])
		txts = append(txts, hex.EncodeToString(raw[:rem/2]))
	}

	return txts
}

func TestDelegate(t *testing.T) {
	tstest.ResourceCheck(t)

	if !ipv6Works() {
		t.Skip("skipping test that requires localhost IPv6")
	}

	randSource := rand.NewSource(4)

	// smallTXT does not require EDNS
	smallTXT := generateTXT(300, randSource)

	// medTXT and largeTXT are responses that require EDNS but we would like to
	// support these sizes of response without truncation because they are
	// moderately common.
	medTXT := generateTXT(1200, randSource)
	largeTXT := generateTXT(3900, randSource)

	// xlargeTXT is slightly above the maximum response size that we support,
	// so there should be truncation.
	xlargeTXT := generateTXT(5000, randSource)

	// hugeTXT is significantly larger than any typical MTU and will require
	// significant fragmentation. For buffer management reasons, we do not
	// intend to handle responses this large, so there should be truncation.
	hugeTXT := generateTXT(64000, randSource)

	records := []interface{}{
		"test.site.",
		resolveToIP(testipv4, testipv6, "dns.test.site."),
		"LCtesT.SiTe.",
		resolveToIPLowercase(testipv4, testipv6, "dns.test.site."),
		"nxdomain.site.", resolveToNXDOMAIN,
		"small.txt.", resolveToTXT(smallTXT, noEdns),
		"smalledns.txt.", resolveToTXT(smallTXT, 512),
		"med.txt.", resolveToTXT(medTXT, 1500),
		"large.txt.", resolveToTXT(largeTXT, maxResponseBytes),
		"xlarge.txt.", resolveToTXT(xlargeTXT, 8000),
		"huge.txt.", resolveToTXT(hugeTXT, 65527),
	}
	v4server := serveDNS(t, "127.0.0.1:0", records...)
	defer v4server.Shutdown()
	v6server := serveDNS(t, "[::1]:0", records...)
	defer v6server.Shutdown()

	r := newResolver(t)
	defer r.Close()

	cfg := dnsCfg
	cfg.Routes = map[dnsname.FQDN][]netaddr.IPPort{
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
			dnspacket("test.site.", dns.TypeA, noEdns),
			dnsResponse{ip: testipv4, rcode: dns.RCodeSuccess},
		},
		{
			"ipv6",
			dnspacket("test.site.", dns.TypeAAAA, noEdns),
			dnsResponse{ip: testipv6, rcode: dns.RCodeSuccess},
		},
		{
			"ns",
			dnspacket("test.site.", dns.TypeNS, noEdns),
			dnsResponse{name: "dns.test.site.", rcode: dns.RCodeSuccess},
		},
		{
			"ipv4",
			dnspacket("LCtesT.SiTe.", dns.TypeA, noEdns),
			dnsResponse{ip: testipv4, rcode: dns.RCodeSuccess},
		},
		{
			"ipv6",
			dnspacket("LCtesT.SiTe.", dns.TypeAAAA, noEdns),
			dnsResponse{ip: testipv6, rcode: dns.RCodeSuccess},
		},
		{
			"ns",
			dnspacket("LCtesT.SiTe.", dns.TypeNS, noEdns),
			dnsResponse{name: "dns.test.site.", rcode: dns.RCodeSuccess},
		},
		{
			"nxdomain",
			dnspacket("nxdomain.site.", dns.TypeA, noEdns),
			dnsResponse{rcode: dns.RCodeNameError},
		},
		{
			"smalltxt",
			dnspacket("small.txt.", dns.TypeTXT, 8000),
			dnsResponse{txt: smallTXT, rcode: dns.RCodeSuccess, requestEdns: true, requestEdnsSize: maxResponseBytes},
		},
		{
			"smalltxtedns",
			dnspacket("smalledns.txt.", dns.TypeTXT, 512),
			dnsResponse{
				txt:              smallTXT,
				rcode:            dns.RCodeSuccess,
				requestEdns:      true,
				requestEdnsSize:  512,
				responseEdns:     true,
				responseEdnsSize: 512,
			},
		},
		{
			"medtxt",
			dnspacket("med.txt.", dns.TypeTXT, 2000),
			dnsResponse{
				txt:              medTXT,
				rcode:            dns.RCodeSuccess,
				requestEdns:      true,
				requestEdnsSize:  2000,
				responseEdns:     true,
				responseEdnsSize: 1500,
			},
		},
		{
			"largetxt",
			dnspacket("large.txt.", dns.TypeTXT, maxResponseBytes),
			dnsResponse{
				txt:              largeTXT,
				rcode:            dns.RCodeSuccess,
				requestEdns:      true,
				requestEdnsSize:  maxResponseBytes,
				responseEdns:     true,
				responseEdnsSize: maxResponseBytes,
			},
		},
		{
			"xlargetxt",
			dnspacket("xlarge.txt.", dns.TypeTXT, 8000),
			dnsResponse{
				rcode:     dns.RCodeSuccess,
				truncated: true,
				// request/response EDNS fields will be unset because of
				// they were truncated away
			},
		},
		{
			"hugetxt",
			dnspacket("huge.txt.", dns.TypeTXT, 8000),
			dnsResponse{
				rcode:     dns.RCodeSuccess,
				truncated: true,
				// request/response EDNS fields will be unset because of
				// they were truncated away
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			if tt.title == "hugetxt" && runtime.GOOS == "darwin" {
				t.Skip("known to not work on macOS: https://github.com/tailscale/tailscale/issues/2229")
			}
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
			if len(response.txt) != len(tt.response.txt) {
				t.Errorf("%v txt records, want %v txt records", len(response.txt), len(tt.response.txt))
			} else {
				for i := range response.txt {
					if response.txt[i] != tt.response.txt[i] {
						t.Errorf("txt record %v is %s, want %s", i, response.txt[i], tt.response.txt[i])
					}
				}
			}
			if response.requestEdns != tt.response.requestEdns {
				t.Errorf("requestEdns = %v; want %v", response.requestEdns, tt.response.requestEdns)
			}
			if response.requestEdnsSize != tt.response.requestEdnsSize {
				t.Errorf("requestEdnsSize = %v; want %v", response.requestEdnsSize, tt.response.requestEdnsSize)
			}
			if response.responseEdns != tt.response.responseEdns {
				t.Errorf("responseEdns = %v; want %v", response.requestEdns, tt.response.requestEdns)
			}
			if response.responseEdnsSize != tt.response.responseEdnsSize {
				t.Errorf("responseEdnsSize = %v; want %v", response.responseEdnsSize, tt.response.responseEdnsSize)
			}
		})
	}
}

func TestDelegateSplitRoute(t *testing.T) {
	test4 := netaddr.MustParseIP("2.3.4.5")
	test6 := netaddr.MustParseIP("ff::1")

	server1 := serveDNS(t, "127.0.0.1:0",
		"test.site.", resolveToIP(testipv4, testipv6, "dns.test.site."))
	defer server1.Shutdown()
	server2 := serveDNS(t, "127.0.0.1:0",
		"test.other.", resolveToIP(test4, test6, "dns.other."))
	defer server2.Shutdown()

	r := newResolver(t)
	defer r.Close()

	cfg := dnsCfg
	cfg.Routes = map[dnsname.FQDN][]netaddr.IPPort{
		".":      {netaddr.MustParseIPPort(server1.PacketConn.LocalAddr().String())},
		"other.": {netaddr.MustParseIPPort(server2.PacketConn.LocalAddr().String())},
	}
	r.SetConfig(cfg)

	tests := []struct {
		title    string
		query    []byte
		response dnsResponse
	}{
		{
			"general",
			dnspacket("test.site.", dns.TypeA, noEdns),
			dnsResponse{ip: testipv4, rcode: dns.RCodeSuccess},
		},
		{
			"override",
			dnspacket("test.other.", dns.TypeA, noEdns),
			dnsResponse{ip: test4, rcode: dns.RCodeSuccess},
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
	server := serveDNS(t, "127.0.0.1:0",
		"test.site.", resolveToIP(testipv4, testipv6, "dns.test.site."))
	defer server.Shutdown()

	r := newResolver(t)
	defer r.Close()

	cfg := dnsCfg
	cfg.Routes = map[dnsname.FQDN][]netaddr.IPPort{
		".": {
			netaddr.MustParseIPPort(server.PacketConn.LocalAddr().String()),
		},
	}
	r.SetConfig(cfg)

	packets := []struct {
		qname dnsname.FQDN
		qtype dns.Type
		addr  netaddr.IPPort
	}{
		{"test.site.", dns.TypeA, netaddr.IPPortFrom(netaddr.IPv4(1, 1, 1, 1), 1001)},
		{"test.site.", dns.TypeAAAA, netaddr.IPPortFrom(netaddr.IPv4(1, 1, 1, 1), 1002)},
	}

	// packets will have the same dns txid.
	for _, p := range packets {
		payload := dnspacket(p.qname, p.qtype, noEdns)
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
	r := newResolver(t)
	defer r.Close()

	r.SetConfig(dnsCfg)

	// One full packet and one error packet
	tests := []struct {
		name     string
		request  []byte
		response []byte
	}{
		{"all", dnspacket("test1.ipn.dev.", dns.TypeALL, noEdns), allResponse},
		{"ipv4", dnspacket("test1.ipn.dev.", dns.TypeA, noEdns), ipv4Response},
		{"ipv6", dnspacket("test2.ipn.dev.", dns.TypeAAAA, noEdns), ipv6Response},
		{"no-ipv6", dnspacket("test1.ipn.dev.", dns.TypeAAAA, noEdns), emptyResponse},
		{"upper", dnspacket("TEST1.IPN.DEV.", dns.TypeA, noEdns), ipv4UppercaseResponse},
		{"ptr4", dnspacket("4.3.2.1.in-addr.arpa.", dns.TypePTR, noEdns), ptrResponse},
		{"ptr6", dnspacket("f.0.e.0.d.0.c.0.b.0.a.0.9.0.8.0.7.0.6.0.5.0.4.0.3.0.2.0.1.0.0.0.ip6.arpa.",
			dns.TypePTR, noEdns), ptrResponse6},
		{"nxdomain", dnspacket("test3.ipn.dev.", dns.TypeA, noEdns), nxdomainResponse},
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
	r := newResolver(t)
	defer r.Close()
	r.SetConfig(dnsCfg)

	// It is seemingly pointless to test allocs in the delegate path,
	// as dialer.Dial -> Read -> Write alone comprise 12 allocs.
	tests := []struct {
		name  string
		query []byte
		want  int
	}{
		// Name lowercasing, response slice created by dns.NewBuilder,
		// and closure allocation from go call.
		// (Closure allocation only happens when using new register ABI,
		// which is amd64 with Go 1.17, and probably more platforms later.)
		{"forward", dnspacket("test1.ipn.dev.", dns.TypeA, noEdns), 3},
		// 3 extra allocs in rdnsNameToIPv4 and one in marshalPTRRecord (dns.NewName).
		{"reverse", dnspacket("4.3.2.1.in-addr.arpa.", dns.TypePTR, noEdns), 5},
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
		in   dnsname.FQDN
		want bool
	}{
		{"b._dns-sd._udp.0.10.20.172.in-addr.arpa.", true},
		{"db._dns-sd._udp.0.10.20.172.in-addr.arpa.", true},
		{"r._dns-sd._udp.0.10.20.172.in-addr.arpa.", true},
		{"dr._dns-sd._udp.0.10.20.172.in-addr.arpa.", true},
		{"lb._dns-sd._udp.0.10.20.172.in-addr.arpa.", true},
		{"qq._dns-sd._udp.0.10.20.172.in-addr.arpa.", false},
		{"0.10.20.172.in-addr.arpa.", false},
	}

	for _, test := range tests {
		got := hasRDNSBonjourPrefix(test.in)
		if got != test.want {
			t.Errorf("trimRDNSBonjourPrefix(%q) = %v, want %v", test.in, got, test.want)
		}
	}
}

func BenchmarkFull(b *testing.B) {
	server := serveDNS(b, "127.0.0.1:0",
		"test.site.", resolveToIP(testipv4, testipv6, "dns.test.site."))
	defer server.Shutdown()

	r := newResolver(b)
	defer r.Close()

	cfg := dnsCfg
	cfg.Routes = map[dnsname.FQDN][]netaddr.IPPort{
		".": {
			netaddr.MustParseIPPort(server.PacketConn.LocalAddr().String()),
		},
	}

	tests := []struct {
		name    string
		request []byte
	}{
		{"forward", dnspacket("test1.ipn.dev.", dns.TypeA, noEdns)},
		{"reverse", dnspacket("4.3.2.1.in-addr.arpa.", dns.TypePTR, noEdns)},
		{"delegated", dnspacket("test.site.", dns.TypeA, noEdns)},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
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

func TestForwardLinkSelection(t *testing.T) {
	old := initListenConfig
	defer func() { initListenConfig = old }()

	configCall := make(chan string, 1)
	initListenConfig = func(nc *net.ListenConfig, mon *monitor.Mon, tunName string) error {
		select {
		case configCall <- tunName:
			return nil
		default:
			t.Error("buffer full")
			return errors.New("buffer full")
		}
	}

	// specialIP is some IP we pretend that our link selector
	// routes differently.
	specialIP := netaddr.IPv4(1, 2, 3, 4)

	fwd := newForwarder(t.Logf, nil, nil, linkSelFunc(func(ip netaddr.IP) string {
		if ip == netaddr.IPv4(1, 2, 3, 4) {
			return "special"
		}
		return ""
	}))

	// Test non-special IP.
	if got, err := fwd.packetListener(netaddr.IP{}); err != nil {
		t.Fatal(err)
	} else if got != stdNetPacketListener {
		t.Errorf("for IP zero value, didn't get expected packet listener")
	}
	select {
	case v := <-configCall:
		t.Errorf("unexpected ListenConfig call, with tunName %q", v)
	default:
	}

	// Test that our special IP generates a call to initListenConfig.
	if got, err := fwd.packetListener(specialIP); err != nil {
		t.Fatal(err)
	} else if got == stdNetPacketListener {
		t.Errorf("special IP returned std packet listener; expected unique one")
	}
	if v, ok := <-configCall; !ok {
		t.Errorf("didn't get ListenConfig call")
	} else if v != "special" {
		t.Errorf("got tunName %q; want 'special'", v)
	}
}

type linkSelFunc func(ip netaddr.IP) string

func (f linkSelFunc) PickLink(ip netaddr.IP) string { return f(ip) }
