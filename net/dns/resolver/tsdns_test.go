// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	miekdns "github.com/miekg/dns"
	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/health"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

var (
	testipv4 = netip.MustParseAddr("1.2.3.4")
	testipv6 = netip.MustParseAddr("0001:0203:0405:0607:0809:0a0b:0c0d:0e0f")

	testipv4Arpa = dnsname.FQDN("4.3.2.1.in-addr.arpa.")
	testipv6Arpa = dnsname.FQDN("f.0.e.0.d.0.c.0.b.0.a.0.9.0.8.0.7.0.6.0.5.0.4.0.3.0.2.0.1.0.0.0.ip6.arpa.")
)

var dnsCfg = Config{
	Hosts: map[dnsname.FQDN][]netip.Addr{
		"test1.ipn.dev.": {testipv4},
		"test2.ipn.dev.": {testipv6},
	},
	LocalDomains: []dnsname.FQDN{"ipn.dev.", "3.2.1.in-addr.arpa.", "1.0.0.0.ip6.arpa."},
}

const noEdns = 0

const dnsHeaderLen = 12

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
	ip               netip.Addr
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
			response.ip = netip.AddrFrom16(res.AAAA)
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
	return r.Query(context.Background(), query, "udp", netip.AddrPort{})
}

func mustIP(str string) netip.Addr {
	ip, err := netip.ParseAddr(str)
	if err != nil {
		panic(err)
	}
	return ip
}

func TestRoutesRequireNoCustomResolvers(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected bool
	}{
		{"noRoutes", Config{Routes: map[dnsname.FQDN][]*dnstype.Resolver{}}, true},
		{"onlyDefault", Config{Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			"ts.net.": {
				{},
			},
		}}, true},
		{"oneOther", Config{Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			"example.com.": {
				{},
			},
		}}, false},
		{"defaultAndOneOther", Config{Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			"ts.net.": {
				{},
			},
			"example.com.": {
				{},
			},
		}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.RoutesRequireNoCustomResolvers()
			if result != tt.expected {
				t.Errorf("result = %v; want %v", result, tt.expected)
			}
		})
	}
}

func TestRDNSNameToIPv4(t *testing.T) {
	tests := []struct {
		name   string
		input  dnsname.FQDN
		wantIP netip.Addr
		wantOK bool
	}{
		{"valid", "4.123.24.1.in-addr.arpa.", netaddr.IPv4(1, 24, 123, 4), true},
		{"double_dot", "1..2.3.in-addr.arpa.", netip.Addr{}, false},
		{"overflow", "1.256.3.4.in-addr.arpa.", netip.Addr{}, false},
		{"not_ip", "sub.do.ma.in.in-addr.arpa.", netip.Addr{}, false},
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
		wantIP netip.Addr
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
			netip.Addr{},
			false,
		},
		{
			"double_hex",
			"b.a.98.0.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			netip.Addr{},
			false,
		},
		{
			"not_hex",
			"b.a.g.0.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			netip.Addr{},
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
	return New(t.Logf,
		nil, // no link selector
		tsdial.NewDialer(netmon.NewStatic()),
		new(health.Tracker),
		nil, // no control knobs
	)
}

func TestResolveLocal(t *testing.T) {
	r := newResolver(t)
	defer r.Close()

	r.SetConfig(dnsCfg)

	tests := []struct {
		name  string
		qname dnsname.FQDN
		qtype dns.Type
		ip    netip.Addr
		code  dns.RCode
	}{
		{"ipv4", "test1.ipn.dev.", dns.TypeA, testipv4, dns.RCodeSuccess},
		{"ipv6", "test2.ipn.dev.", dns.TypeAAAA, testipv6, dns.RCodeSuccess},
		{"no-ipv6", "test1.ipn.dev.", dns.TypeAAAA, netip.Addr{}, dns.RCodeSuccess},
		{"nxdomain", "test3.ipn.dev.", dns.TypeA, netip.Addr{}, dns.RCodeNameError},
		{"foreign domain", "google.com.", dns.TypeA, netip.Addr{}, dns.RCodeRefused},
		{"all", "test1.ipn.dev.", dns.TypeA, testipv4, dns.RCodeSuccess},
		{"mx-ipv4", "test1.ipn.dev.", dns.TypeMX, netip.Addr{}, dns.RCodeSuccess},
		{"mx-ipv6", "test2.ipn.dev.", dns.TypeMX, netip.Addr{}, dns.RCodeSuccess},
		{"mx-nxdomain", "test3.ipn.dev.", dns.TypeMX, netip.Addr{}, dns.RCodeNameError},
		{"ns-nxdomain", "test3.ipn.dev.", dns.TypeNS, netip.Addr{}, dns.RCodeNameError},
		{"onion-domain", "footest.onion.", dns.TypeA, netip.Addr{}, dns.RCodeNameError},
		{"magicdns", dnsSymbolicFQDN, dns.TypeA, netip.MustParseAddr("100.100.100.100"), dns.RCodeSuccess},
		{"via_hex", dnsname.FQDN("via-0xff.1.2.3.4."), dns.TypeAAAA, netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:ff:1.2.3.4"), dns.RCodeSuccess},
		{"via_dec", dnsname.FQDN("via-1.10.0.0.1."), dns.TypeAAAA, netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:10.0.0.1"), dns.RCodeSuccess},
		{"x_via_hex", dnsname.FQDN("4.3.2.1.via-0xff."), dns.TypeAAAA, netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:ff:4.3.2.1"), dns.RCodeSuccess},
		{"x_via_dec", dnsname.FQDN("1.0.0.10.via-1."), dns.TypeAAAA, netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:1.0.0.10"), dns.RCodeSuccess},
		{"via_invalid", dnsname.FQDN("via-."), dns.TypeAAAA, netip.Addr{}, dns.RCodeRefused},
		{"via_invalid_2", dnsname.FQDN("2.3.4.5.via-."), dns.TypeAAAA, netip.Addr{}, dns.RCodeRefused},

		// Hyphenated 4via6 format.
		// Without any suffix domain:
		{"via_form3_hex_bare", dnsname.FQDN("1-2-3-4-via-0xff."), dns.TypeAAAA, netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:ff:1.2.3.4"), dns.RCodeSuccess},
		{"via_form3_dec_bare", dnsname.FQDN("1-2-3-4-via-1."), dns.TypeAAAA, netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:1.2.3.4"), dns.RCodeSuccess},
		// With a Tailscale domain:
		{"via_form3_dec_ts.net", dnsname.FQDN("1-2-3-4-via-1.foo.ts.net."), dns.TypeAAAA, netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:1.2.3.4"), dns.RCodeSuccess},
		{"via_form3_dec_tailscale.net", dnsname.FQDN("1-2-3-4-via-1.foo.tailscale.net."), dns.TypeAAAA, netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:1.2.3.4"), dns.RCodeSuccess},
		// Non-Tailscale domain suffixes aren't allowed for now: (the allowed
		// suffixes are currently hard-coded and not plumbed via the netmap)
		{"via_form3_dec_example.com", dnsname.FQDN("1-2-3-4-via-1.example.com."), dns.TypeAAAA, netip.Addr{}, dns.RCodeRefused},
		{"via_form3_dec_examplets.net", dnsname.FQDN("1-2-3-4-via-1.examplets.net."), dns.TypeAAAA, netip.Addr{}, dns.RCodeRefused},

		// Resolve A and ALL types of resource records.
		{"via_type_a", dnsname.FQDN("1-2-3-4-via-1."), dns.TypeA, netip.Addr{}, dns.RCodeSuccess},
		{"via_invalid_type_a", dnsname.FQDN("1-2-3-4-via-."), dns.TypeA, netip.Addr{}, dns.RCodeRefused},
		{"via_type_all", dnsname.FQDN("1-2-3-4-via-1."), dns.TypeALL, netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1:1.2.3.4"), dns.RCodeSuccess},
		{"via_invalid_type_all", dnsname.FQDN("1-2-3-4-via-."), dns.TypeALL, netip.Addr{}, dns.RCodeRefused},
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
		q    dnsname.FQDN
		want dnsname.FQDN
		code dns.RCode
	}{
		{"ipv4", testipv4Arpa, "test1.ipn.dev.", dns.RCodeSuccess},
		{"ipv6", testipv6Arpa, "test2.ipn.dev.", dns.RCodeSuccess},
		{"ipv4_nxdomain", dnsname.FQDN("5.3.2.1.in-addr.arpa."), "", dns.RCodeNameError},
		{"ipv6_nxdomain", dnsname.FQDN("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.ip6.arpa."), "", dns.RCodeNameError},
		{"nxdomain", dnsname.FQDN("2.3.4.5.in-addr.arpa."), "", dns.RCodeRefused},
		{"magicdns", dnsname.FQDN("100.100.100.100.in-addr.arpa."), dnsSymbolicFQDN, dns.RCodeSuccess},
		{"ipv6_4to6", dnsname.FQDN("4.6.4.6.4.6.2.6.6.9.d.c.3.4.8.4.2.1.b.a.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."), dnsSymbolicFQDN, dns.RCodeSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, code := r.resolveLocalReverse(tt.q)
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

	records := []any{
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
	cfg.Routes = map[dnsname.FQDN][]*dnstype.Resolver{
		".": {
			&dnstype.Resolver{Addr: v4server.PacketConn.LocalAddr().String()},
			&dnstype.Resolver{Addr: v6server.PacketConn.LocalAddr().String()},
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
	test4 := netip.MustParseAddr("2.3.4.5")
	test6 := netip.MustParseAddr("ff::1")

	server1 := serveDNS(t, "127.0.0.1:0",
		"test.site.", resolveToIP(testipv4, testipv6, "dns.test.site."))
	defer server1.Shutdown()
	server2 := serveDNS(t, "127.0.0.1:0",
		"test.other.", resolveToIP(test4, test6, "dns.other."))
	defer server2.Shutdown()

	r := newResolver(t)
	defer r.Close()

	cfg := dnsCfg
	cfg.Routes = map[dnsname.FQDN][]*dnstype.Resolver{
		".":      {{Addr: server1.PacketConn.LocalAddr().String()}},
		"other.": {{Addr: server2.PacketConn.LocalAddr().String()}},
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
		want  uint64
	}{
		// Name lowercasing, response slice created by dns.NewBuilder,
		// and closure allocation from go call.
		{"forward", dnspacket("test1.ipn.dev.", dns.TypeA, noEdns), 3},
		// 3 extra allocs in rdnsNameToIPv4 and one in marshalPTRRecord (dns.NewName).
		{"reverse", dnspacket("4.3.2.1.in-addr.arpa.", dns.TypePTR, noEdns), 5},
	}

	for _, tt := range tests {
		err := tstest.MinAllocsPerRun(t, tt.want, func() {
			syncRespond(r, tt.query)
		})
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
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
		{"lb._dns-sd._udp.ts-dns.test.", true},
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
	cfg.Routes = map[dnsname.FQDN][]*dnstype.Resolver{
		".": {{Addr: server.PacketConn.LocalAddr().String()}},
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
			for range b.N {
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
	configCall := make(chan string, 1)
	tstest.Replace(t, &initListenConfig, func(nc *net.ListenConfig, netMon *netmon.Monitor, tunName string) error {
		select {
		case configCall <- tunName:
			return nil
		default:
			t.Error("buffer full")
			return errors.New("buffer full")
		}
	})

	// specialIP is some IP we pretend that our link selector
	// routes differently.
	specialIP := netaddr.IPv4(1, 2, 3, 4)

	netMon, err := netmon.New(logger.WithPrefix(t.Logf, ".... netmon: "))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netMon.Close() })

	fwd := newForwarder(t.Logf, netMon, linkSelFunc(func(ip netip.Addr) string {
		if ip == netaddr.IPv4(1, 2, 3, 4) {
			return "special"
		}
		return ""
	}), new(tsdial.Dialer), new(health.Tracker), nil /* no control knobs */)

	// Test non-special IP.
	if got, err := fwd.packetListener(netip.Addr{}); err != nil {
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

type linkSelFunc func(ip netip.Addr) string

func (f linkSelFunc) PickLink(ip netip.Addr) string { return f(ip) }

func TestHandleExitNodeDNSQueryWithNetPkg(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test on Windows; waiting for golang.org/issue/33097")
	}

	records := []any{
		"no-records.test.",
		dnsHandler(),

		"one-a.test.",
		dnsHandler(netip.MustParseAddr("1.2.3.4")),

		"two-a.test.",
		dnsHandler(netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")),

		"one-aaaa.test.",
		dnsHandler(netip.MustParseAddr("1::2")),

		"two-aaaa.test.",
		dnsHandler(netip.MustParseAddr("1::2"), netip.MustParseAddr("3::4")),

		"nx-domain.test.",
		resolveToNXDOMAIN,

		"4.3.2.1.in-addr.arpa.",
		dnsHandler(miekdns.PTR{Ptr: "foo.com."}),

		"cname.test.",
		weirdoGoCNAMEHandler("the-target.foo."),

		"txt.test.",
		dnsHandler(
			miekdns.TXT{Txt: []string{"txt1=one"}},
			miekdns.TXT{Txt: []string{"txt2=two"}},
			miekdns.TXT{Txt: []string{"txt3=three"}},
		),

		"srv.test.",
		dnsHandler(
			miekdns.SRV{
				Priority: 1,
				Weight:   2,
				Port:     3,
				Target:   "foo.com.",
			},
			miekdns.SRV{
				Priority: 4,
				Weight:   5,
				Port:     6,
				Target:   "bar.com.",
			},
		),

		"ns.test.",
		dnsHandler(miekdns.NS{Ns: "ns1.foo."}, miekdns.NS{Ns: "ns2.bar."}),
	}
	v4server := serveDNS(t, "127.0.0.1:0", records...)
	defer v4server.Shutdown()

	// backendResolver is the resolver between
	// handleExitNodeDNSQueryWithNetPkg and its upstream resolver,
	// which in this test's case is the miekg/dns test DNS server
	// (v4server).
	backResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", v4server.PacketConn.LocalAddr().String())
		},
	}

	t.Run("no_such_host", func(t *testing.T) {
		res, err := handleExitNodeDNSQueryWithNetPkg(context.Background(), t.Logf, backResolver, &response{
			Header: dns.Header{
				ID:       123,
				Response: true,
				OpCode:   0, // query
			},
			Question: dns.Question{
				Name:  dns.MustNewName("nx-domain.test."),
				Type:  dns.TypeA,
				Class: dns.ClassINET,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) < dnsHeaderLen {
			t.Fatal("short reply")
		}
		rcode := dns.RCode(res[3] & 0x0f)
		if rcode != dns.RCodeNameError {
			t.Errorf("RCode = %v; want dns.RCodeNameError", rcode)
			t.Logf("Response was: %q", res)
		}
	})

	matchPacked := func(want string) func(t testing.TB, got []byte) {
		return func(t testing.TB, got []byte) {
			if string(got) == want {
				return
			}
			t.Errorf("unexpected reply.\n got: %q\nwant: %q\n", got, want)
			t.Errorf("\nin hex:\n got: % 2x\nwant: % 2x\n", got, want)
		}
	}

	tests := []struct {
		Type  dns.Type
		Name  string
		Check func(t testing.TB, got []byte)
	}{
		{
			Type:  dns.TypeA,
			Name:  "one-a.test.",
			Check: matchPacked("\x00{\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05one-a\x04test\x00\x00\x01\x00\x01\x05one-a\x04test\x00\x00\x01\x00\x01\x00\x00\x02X\x00\x04\x01\x02\x03\x04"),
		},
		{
			Type:  dns.TypeA,
			Name:  "two-a.test.",
			Check: matchPacked("\x00{\x84\x00\x00\x01\x00\x02\x00\x00\x00\x00\x05two-a\x04test\x00\x00\x01\x00\x01\xc0\f\x00\x01\x00\x01\x00\x00\x02X\x00\x04\x01\x02\x03\x04\xc0\f\x00\x01\x00\x01\x00\x00\x02X\x00\x04\x05\x06\a\b"),
		},
		{
			Type:  dns.TypeAAAA,
			Name:  "one-aaaa.test.",
			Check: matchPacked("\x00{\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\bone-aaaa\x04test\x00\x00\x1c\x00\x01\bone-aaaa\x04test\x00\x00\x1c\x00\x01\x00\x00\x02X\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"),
		},
		{
			Type:  dns.TypeAAAA,
			Name:  "two-aaaa.test.",
			Check: matchPacked("\x00{\x84\x00\x00\x01\x00\x02\x00\x00\x00\x00\btwo-aaaa\x04test\x00\x00\x1c\x00\x01\xc0\f\x00\x1c\x00\x01\x00\x00\x02X\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\xc0\f\x00\x1c\x00\x01\x00\x00\x02X\x00\x10\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"),
		},
		{
			Type:  dns.TypePTR,
			Name:  "4.3.2.1.in-addr.arpa.",
			Check: matchPacked("\x00{\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x014\x013\x012\x011\ain-addr\x04arpa\x00\x00\f\x00\x01\x014\x013\x012\x011\ain-addr\x04arpa\x00\x00\f\x00\x01\x00\x00\x02X\x00\t\x03foo\x03com\x00"),
		},
		{
			Type:  dns.TypeCNAME,
			Name:  "cname.test.",
			Check: matchPacked("\x00{\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05cname\x04test\x00\x00\x05\x00\x01\x05cname\x04test\x00\x00\x05\x00\x01\x00\x00\x02X\x00\x10\nthe-target\x03foo\x00"),
		},

		// No records of various types
		{
			Type:  dns.TypeA,
			Name:  "no-records.test.",
			Check: matchPacked("\x00{\x84\x03\x00\x01\x00\x00\x00\x00\x00\x00\nno-records\x04test\x00\x00\x01\x00\x01"),
		},
		{
			Type:  dns.TypeAAAA,
			Name:  "no-records.test.",
			Check: matchPacked("\x00{\x84\x03\x00\x01\x00\x00\x00\x00\x00\x00\nno-records\x04test\x00\x00\x1c\x00\x01"),
		},
		{
			Type:  dns.TypeCNAME,
			Name:  "no-records.test.",
			Check: matchPacked("\x00{\x84\x03\x00\x01\x00\x00\x00\x00\x00\x00\nno-records\x04test\x00\x00\x05\x00\x01"),
		},
		{
			Type:  dns.TypeSRV,
			Name:  "no-records.test.",
			Check: matchPacked("\x00{\x84\x03\x00\x01\x00\x00\x00\x00\x00\x00\nno-records\x04test\x00\x00!\x00\x01"),
		},
		{
			Type:  dns.TypeTXT,
			Name:  "txt.test.",
			Check: matchPacked("\x00{\x84\x00\x00\x01\x00\x03\x00\x00\x00\x00\x03txt\x04test\x00\x00\x10\x00\x01\x03txt\x04test\x00\x00\x10\x00\x01\x00\x00\x02X\x00\t\btxt1=one\x03txt\x04test\x00\x00\x10\x00\x01\x00\x00\x02X\x00\t\btxt2=two\x03txt\x04test\x00\x00\x10\x00\x01\x00\x00\x02X\x00\v\ntxt3=three"),
		},
		{
			Type:  dns.TypeSRV,
			Name:  "srv.test.",
			Check: matchPacked("\x00{\x84\x00\x00\x01\x00\x02\x00\x00\x00\x00\x03srv\x04test\x00\x00!\x00\x01\x03srv\x04test\x00\x00!\x00\x01\x00\x00\x02X\x00\x0f\x00\x01\x00\x02\x00\x03\x03foo\x03com\x00\x03srv\x04test\x00\x00!\x00\x01\x00\x00\x02X\x00\x0f\x00\x04\x00\x05\x00\x06\x03bar\x03com\x00"),
		},
		{
			Type:  dns.TypeNS,
			Name:  "ns.test.",
			Check: matchPacked("\x00{\x84\x00\x00\x01\x00\x02\x00\x00\x00\x00\x02ns\x04test\x00\x00\x02\x00\x01\x02ns\x04test\x00\x00\x02\x00\x01\x00\x00\x02X\x00\t\x03ns1\x03foo\x00\x02ns\x04test\x00\x00\x02\x00\x01\x00\x00\x02X\x00\t\x03ns2\x03bar\x00"),
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v_%v", tt.Type, strings.Trim(tt.Name, ".")), func(t *testing.T) {
			got, err := handleExitNodeDNSQueryWithNetPkg(context.Background(), t.Logf, backResolver, &response{
				Header: dns.Header{
					ID:       123,
					Response: true,
					OpCode:   0, // query
				},
				Question: dns.Question{
					Name:  dns.MustNewName(tt.Name),
					Type:  tt.Type,
					Class: dns.ClassINET,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) < dnsHeaderLen {
				t.Errorf("short record")
			}
			if tt.Check != nil {
				tt.Check(t, got)
				if t.Failed() {
					t.Errorf("Got: %q\nIn hex: % 02x", got, got)
				}
			}
		})
	}

	wrapRes := newWrapResolver(backResolver)
	ctx := context.Background()

	t.Run("wrap_ip_a", func(t *testing.T) {
		ips, err := wrapRes.LookupIP(ctx, "ip", "two-a.test.")
		if err != nil {
			t.Fatal(err)
		}
		if got, want := ips, []net.IP{
			net.ParseIP("1.2.3.4").To4(),
			net.ParseIP("5.6.7.8").To4(),
		}; !reflect.DeepEqual(got, want) {
			t.Errorf("LookupIP = %v; want %v", got, want)
		}
	})

	t.Run("wrap_ip_aaaa", func(t *testing.T) {
		ips, err := wrapRes.LookupIP(ctx, "ip", "two-aaaa.test.")
		if err != nil {
			t.Fatal(err)
		}
		if got, want := ips, []net.IP{
			net.ParseIP("1::2"),
			net.ParseIP("3::4"),
		}; !reflect.DeepEqual(got, want) {
			t.Errorf("LookupIP(v6) = %v; want %v", got, want)
		}
	})

	t.Run("wrap_ip_nx", func(t *testing.T) {
		ips, err := wrapRes.LookupIP(ctx, "ip", "nx-domain.test.")
		if !isGoNoSuchHostError(err) {
			t.Errorf("no NX domain = (%v, %v); want no host error", ips, err)
		}
	})

	t.Run("wrap_srv", func(t *testing.T) {
		_, srvs, err := wrapRes.LookupSRV(ctx, "", "", "srv.test.")
		if err != nil {
			t.Fatal(err)
		}
		if got, want := srvs, []*net.SRV{
			{
				Target:   "foo.com.",
				Priority: 1,
				Weight:   2,
				Port:     3,
			},
			{
				Target:   "bar.com.",
				Priority: 4,
				Weight:   5,
				Port:     6,
			},
		}; !reflect.DeepEqual(got, want) {
			jgot, _ := json.Marshal(got)
			jwant, _ := json.Marshal(want)
			t.Errorf("SRV = %s; want %s", jgot, jwant)
		}
	})

	t.Run("wrap_txt", func(t *testing.T) {
		txts, err := wrapRes.LookupTXT(ctx, "txt.test.")
		if err != nil {
			t.Fatal(err)
		}
		if got, want := txts, []string{"txt1=one", "txt2=two", "txt3=three"}; !reflect.DeepEqual(got, want) {
			t.Errorf("TXT = %q; want %q", got, want)
		}
	})

	t.Run("wrap_ns", func(t *testing.T) {
		nss, err := wrapRes.LookupNS(ctx, "ns.test.")
		if err != nil {
			t.Fatal(err)
		}
		if got, want := nss, []*net.NS{
			{Host: "ns1.foo."},
			{Host: "ns2.bar."},
		}; !reflect.DeepEqual(got, want) {
			jgot, _ := json.Marshal(got)
			jwant, _ := json.Marshal(want)
			t.Errorf("NS = %s; want %s", jgot, jwant)
		}
	})
}

// newWrapResolver returns a resolver that uses r (via handleExitNodeDNSQueryWithNetPkg)
// to make DNS requests.
func newWrapResolver(r *net.Resolver) *net.Resolver {
	if runtime.GOOS == "windows" {
		panic("doesn't work on Windows") // golang.org/issue/33097
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return &wrapResolverConn{ctx: ctx, r: r}, nil
		},
	}
}

type wrapResolverConn struct {
	ctx context.Context
	r   *net.Resolver
	buf bytes.Buffer
}

var _ net.PacketConn = (*wrapResolverConn)(nil)

func (*wrapResolverConn) Close() error                       { return nil }
func (*wrapResolverConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (*wrapResolverConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (*wrapResolverConn) SetDeadline(t time.Time) error      { return nil }
func (*wrapResolverConn) SetReadDeadline(t time.Time) error  { return nil }
func (*wrapResolverConn) SetWriteDeadline(t time.Time) error { return nil }

func (a *wrapResolverConn) Read(p []byte) (n int, err error) {
	n, _, err = a.ReadFrom(p)
	return
}

func (a *wrapResolverConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = a.buf.Read(p)
	return n, fakeAddr{}, err
}

func (a *wrapResolverConn) Write(packet []byte) (n int, err error) {
	return a.WriteTo(packet, fakeAddr{})
}

func (a *wrapResolverConn) WriteTo(q []byte, _ net.Addr) (n int, err error) {
	resp := parseExitNodeQuery(q)
	if resp == nil {
		return 0, errors.New("bad query")
	}
	res, err := handleExitNodeDNSQueryWithNetPkg(context.Background(), log.Printf, a.r, resp)
	if err != nil {
		return 0, err
	}
	a.buf.Write(res)
	return len(q), nil
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "unused" }
func (fakeAddr) String() string  { return "unused-todoAddr" }

func TestUnARPA(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"bad", ""},
		{"4.4.8.8.in-addr.arpa.", "8.8.4.4"},
		{".in-addr.arpa.", ""},
		{"e.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.b.0.8.0.a.0.0.4.0.b.8.f.7.0.6.2.ip6.arpa.", "2607:f8b0:400a:80b::200e"},
		{".ip6.arpa.", ""},
	}
	for _, tt := range tests {
		got, ok := unARPA(tt.in)
		if ok != (got != "") {
			t.Errorf("inconsistent results for %q: (%q, %v)", tt.in, got, ok)
		}
		if got != tt.want {
			t.Errorf("unARPA(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

// TestServfail validates that a SERVFAIL error response is returned if
// all upstream resolvers respond with SERVFAIL.
//
// See: https://github.com/tailscale/tailscale/issues/4722
func TestServfail(t *testing.T) {
	server := serveDNS(t, "127.0.0.1:0", "test.site.", miekdns.HandlerFunc(func(w miekdns.ResponseWriter, req *miekdns.Msg) {
		m := new(miekdns.Msg)
		m.Rcode = miekdns.RcodeServerFailure
		w.WriteMsg(m)
	}))
	defer server.Shutdown()

	r := newResolver(t)
	defer r.Close()

	cfg := dnsCfg
	cfg.Routes = map[dnsname.FQDN][]*dnstype.Resolver{
		".": {{Addr: server.PacketConn.LocalAddr().String()}},
	}
	r.SetConfig(cfg)

	pkt, err := syncRespond(r, dnspacket("test.site.", dns.TypeA, noEdns))
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}

	wantPkt := []byte{
		0x00, 0x00, // transaction id: 0
		0x84, 0x02, // flags: response, authoritative, error: servfail
		0x00, 0x01, // one question
		0x00, 0x00, // no answers
		0x00, 0x00, 0x00, 0x00, // no authority or additional RRs
		// Question:
		0x04, 0x74, 0x65, 0x73, 0x74, 0x04, 0x73, 0x69, 0x74, 0x65, 0x00, // name
		0x00, 0x01, 0x00, 0x01, // type A, class IN
	}

	if !bytes.Equal(pkt, wantPkt) {
		t.Errorf("response was %X, want %X", pkt, wantPkt)
	}
}
