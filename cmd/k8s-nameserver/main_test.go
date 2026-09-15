// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
	"tailscale.com/util/dnsname"
)

func TestNameserver(t *testing.T) {

	tests := []struct {
		name     string
		ip4      map[dnsname.FQDN][]net.IP
		ip6      map[dnsname.FQDN][]net.IP
		query    *dns.Msg
		wantResp *dns.Msg
	}{
		{
			name: "A-record-exists",
			ip4:  map[dnsname.FQDN][]net.IP{dnsname.FQDN("foo.bar.com."): {{1, 2, 3, 4}}},
			query: &dns.Msg{
				Question: []dns.Question{{Name: "foo.bar.com", Qtype: dns.TypeA}},
				MsgHdr:   dns.MsgHdr{Id: 1, RecursionDesired: true},
			},
			wantResp: &dns.Msg{
				Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{
					Name: "foo.bar.com", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A: net.IP{1, 2, 3, 4}}},
				Question: []dns.Question{{Name: "foo.bar.com", Qtype: dns.TypeA}},
				MsgHdr: dns.MsgHdr{
					Id:                 1,
					Rcode:              dns.RcodeSuccess,
					RecursionAvailable: false,
					RecursionDesired:   true,
					Response:           true,
					Opcode:             dns.OpcodeQuery,
					Authoritative:      true,
				}},
		},
		{
			name: "A-record-not-exists",
			ip4:  map[dnsname.FQDN][]net.IP{dnsname.FQDN("foo.bar.com."): {{1, 2, 3, 4}}},
			query: &dns.Msg{
				Question: []dns.Question{{Name: "baz.bar.com", Qtype: dns.TypeA}},
				MsgHdr:   dns.MsgHdr{Id: 1},
			},
			wantResp: &dns.Msg{
				Question: []dns.Question{{Name: "baz.bar.com", Qtype: dns.TypeA}},
				MsgHdr: dns.MsgHdr{
					Id:                 1,
					Rcode:              dns.RcodeNameError,
					RecursionAvailable: false,
					Response:           true,
					Opcode:             dns.OpcodeQuery,
					Authoritative:      true,
				}},
		},
		{
			name: "A-record-invalid-FQDN",
			ip4:  map[dnsname.FQDN][]net.IP{dnsname.FQDN("foo.bar.com."): {{1, 2, 3, 4}}},
			query: &dns.Msg{
				Question: []dns.Question{{Name: "foo..bar.com", Qtype: dns.TypeA}},
				MsgHdr:   dns.MsgHdr{Id: 1},
			},
			wantResp: &dns.Msg{
				Question: []dns.Question{{Name: "foo..bar.com", Qtype: dns.TypeA}},
				MsgHdr: dns.MsgHdr{
					Id:       1,
					Rcode:    dns.RcodeFormatError,
					Response: true,
					Opcode:   dns.OpcodeQuery,
				}},
		},
		{
			name: "AAAA-query-A-record-exists",
			ip4:  map[dnsname.FQDN][]net.IP{dnsname.FQDN("foo.bar.com."): {{1, 2, 3, 4}}},
			query: &dns.Msg{
				Question: []dns.Question{{Name: "foo.bar.com", Qtype: dns.TypeAAAA}},
				MsgHdr:   dns.MsgHdr{Id: 1},
			},
			wantResp: &dns.Msg{
				Question: []dns.Question{{Name: "foo.bar.com", Qtype: dns.TypeAAAA}},
				MsgHdr: dns.MsgHdr{
					Id:            1,
					Rcode:         dns.RcodeSuccess,
					Response:      true,
					Opcode:        dns.OpcodeQuery,
					Authoritative: true,
				}},
		},
		{
			name: "AAAA-query-A-record-not-exists",
			ip4:  map[dnsname.FQDN][]net.IP{dnsname.FQDN("foo.bar.com."): {{1, 2, 3, 4}}},
			query: &dns.Msg{
				Question: []dns.Question{{Name: "baz.bar.com", Qtype: dns.TypeAAAA}},
				MsgHdr:   dns.MsgHdr{Id: 1},
			},
			wantResp: &dns.Msg{
				Question: []dns.Question{{Name: "baz.bar.com", Qtype: dns.TypeAAAA}},
				MsgHdr: dns.MsgHdr{
					Id:            1,
					Rcode:         dns.RcodeNameError,
					Response:      true,
					Opcode:        dns.OpcodeQuery,
					Authoritative: true,
				}},
		},
		{
			name: "AAAA-query-ipv6-record",
			ip6:  map[dnsname.FQDN][]net.IP{dnsname.FQDN("foo.bar.com."): {net.ParseIP("2001:db8::1")}},
			query: &dns.Msg{
				Question: []dns.Question{{Name: "foo.bar.com", Qtype: dns.TypeAAAA}},
				MsgHdr:   dns.MsgHdr{Id: 1, RecursionDesired: true},
			},
			wantResp: &dns.Msg{
				Answer: []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{
					Name: "foo.bar.com", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
					AAAA: net.ParseIP("2001:db8::1")}},
				Question: []dns.Question{{Name: "foo.bar.com", Qtype: dns.TypeAAAA}},
				MsgHdr: dns.MsgHdr{
					Id:                 1,
					Rcode:              dns.RcodeSuccess,
					RecursionAvailable: false,
					RecursionDesired:   true,
					Response:           true,
					Opcode:             dns.OpcodeQuery,
					Authoritative:      true,
				}},
		},
		{
			name: "dual-stack-A-and-AAAA",
			ip4:  map[dnsname.FQDN][]net.IP{dnsname.FQDN("dual.bar.com."): {{10, 0, 0, 1}}},
			ip6:  map[dnsname.FQDN][]net.IP{dnsname.FQDN("dual.bar.com."): {net.ParseIP("2001:db8::1")}},
			query: &dns.Msg{
				Question: []dns.Question{{Name: "dual.bar.com", Qtype: dns.TypeAAAA}},
				MsgHdr:   dns.MsgHdr{Id: 1},
			},
			wantResp: &dns.Msg{
				Answer: []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{
					Name: "dual.bar.com", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
					AAAA: net.ParseIP("2001:db8::1")}},
				Question: []dns.Question{{Name: "dual.bar.com", Qtype: dns.TypeAAAA}},
				MsgHdr: dns.MsgHdr{
					Id:            1,
					Rcode:         dns.RcodeSuccess,
					Response:      true,
					Opcode:        dns.OpcodeQuery,
					Authoritative: true,
				}},
		},
		{
			name: "CNAME-query",
			ip4:  map[dnsname.FQDN][]net.IP{dnsname.FQDN("foo.bar.com."): {{1, 2, 3, 4}}},
			query: &dns.Msg{
				Question: []dns.Question{{Name: "foo.bar.com", Qtype: dns.TypeCNAME}},
				MsgHdr:   dns.MsgHdr{Id: 1},
			},
			wantResp: &dns.Msg{
				Question: []dns.Question{{Name: "foo.bar.com", Qtype: dns.TypeCNAME}},
				MsgHdr: dns.MsgHdr{
					Id:       1,
					Rcode:    dns.RcodeNotImplemented,
					Response: true,
					Opcode:   dns.OpcodeQuery,
				}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := &nameserver{
				ip4: tt.ip4,
				ip6: tt.ip6,
			}
			handler := ns.handleFunc()
			fakeRespW := &fakeResponseWriter{}
			handler(fakeRespW, tt.query)
			if diff := cmp.Diff(*fakeRespW.msg, *tt.wantResp); diff != "" {
				t.Fatalf("unexpected response (-got +want): \n%s", diff)
			}
		})
	}
}

func TestResetRecords(t *testing.T) {
	tests := []struct {
		name     string
		config   []byte
		hasIp4   map[dnsname.FQDN][]net.IP
		hasIp6   map[dnsname.FQDN][]net.IP
		wantsIp4 map[dnsname.FQDN][]net.IP
		wantsIp6 map[dnsname.FQDN][]net.IP
		wantsErr bool
	}{
		{
			name:     "previously-empty-nameserver-ip4-gets-set",
			config:   []byte(`{"version": "v1alpha1", "ip4": {"foo.bar.com": ["1.2.3.4"]}}`),
			wantsIp4: map[dnsname.FQDN][]net.IP{"foo.bar.com.": {{1, 2, 3, 4}}},
			wantsIp6: make(map[dnsname.FQDN][]net.IP),
		},
		{
			name:     "nameserver-ip4-gets-reset",
			hasIp4:   map[dnsname.FQDN][]net.IP{"baz.bar.com.": {{1, 1, 3, 3}}},
			config:   []byte(`{"version": "v1alpha1", "ip4": {"foo.bar.com": ["1.2.3.4"]}}`),
			wantsIp4: map[dnsname.FQDN][]net.IP{"foo.bar.com.": {{1, 2, 3, 4}}},
			wantsIp6: make(map[dnsname.FQDN][]net.IP),
		},
		{
			name:     "configuration-with-incompatible-version",
			hasIp4:   map[dnsname.FQDN][]net.IP{"baz.bar.com.": {{1, 1, 3, 3}}},
			config:   []byte(`{"version": "v1beta1", "ip4": {"foo.bar.com": ["1.2.3.4"]}}`),
			wantsIp4: map[dnsname.FQDN][]net.IP{"baz.bar.com.": {{1, 1, 3, 3}}},
			wantsIp6: nil,
			wantsErr: true,
		},
		{
			name:     "nameserver-ip4-gets-reset-to-empty-config-when-no-configuration-is-provided",
			hasIp4:   map[dnsname.FQDN][]net.IP{"baz.bar.com.": {{1, 1, 3, 3}}},
			wantsIp4: make(map[dnsname.FQDN][]net.IP),
			wantsIp6: make(map[dnsname.FQDN][]net.IP),
		},
		{
			name:     "nameserver-ip4-gets-reset-to-empty-config-when-the-provided-configuration-is-empty",
			hasIp4:   map[dnsname.FQDN][]net.IP{"baz.bar.com.": {{1, 1, 3, 3}}},
			config:   []byte(`{"version": "v1alpha1", "ip4": {}}`),
			wantsIp4: make(map[dnsname.FQDN][]net.IP),
			wantsIp6: make(map[dnsname.FQDN][]net.IP),
		},
		{
			name:     "nameserver-ip6-gets-set",
			config:   []byte(`{"version": "v1alpha1", "ip6": {"foo.bar.com": ["2001:db8::1"]}}`),
			wantsIp4: make(map[dnsname.FQDN][]net.IP),
			wantsIp6: map[dnsname.FQDN][]net.IP{"foo.bar.com.": {net.ParseIP("2001:db8::1")}},
		},
		{
			name:     "dual-stack-configuration",
			config:   []byte(`{"version": "v1alpha1", "ip4": {"dual.bar.com": ["10.0.0.1"]}, "ip6": {"dual.bar.com": ["2001:db8::1"]}}`),
			wantsIp4: map[dnsname.FQDN][]net.IP{"dual.bar.com.": {{10, 0, 0, 1}}},
			wantsIp6: map[dnsname.FQDN][]net.IP{"dual.bar.com.": {net.ParseIP("2001:db8::1")}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := &nameserver{
				ip4:          tt.hasIp4,
				ip6:          tt.hasIp6,
				configReader: func() ([]byte, error) { return tt.config, nil },
			}
			if err := ns.resetRecords(); err == nil == tt.wantsErr {
				t.Errorf("resetRecords() returned err: %v, wantsErr: %v", err, tt.wantsErr)
			}
			if diff := cmp.Diff(ns.ip4, tt.wantsIp4); diff != "" {
				t.Fatalf("unexpected nameserver.ip4 contents (-got +want): \n%s", diff)
			}
			if diff := cmp.Diff(ns.ip6, tt.wantsIp6); diff != "" {
				t.Fatalf("unexpected nameserver.ip6 contents (-got +want): \n%s", diff)
			}
		})
	}
}

// fakeResponseWriter is a faked out dns.ResponseWriter that can be used in
// tests that need to read the response message that was written.
type fakeResponseWriter struct {
	msg *dns.Msg
}

var _ dns.ResponseWriter = &fakeResponseWriter{}

func (fr *fakeResponseWriter) WriteMsg(msg *dns.Msg) error {
	fr.msg = msg
	return nil
}
func (fr *fakeResponseWriter) LocalAddr() net.Addr {
	return nil
}
func (fr *fakeResponseWriter) RemoteAddr() net.Addr {
	return nil
}
func (fr *fakeResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}
func (fr *fakeResponseWriter) Close() error {
	return nil
}
func (fr *fakeResponseWriter) TsigStatus() error {
	return nil
}
func (fr *fakeResponseWriter) TsigTimersOnly(bool) {}
func (fr *fakeResponseWriter) Hijack()             {}

// startUpstream starts an in-process DNS server answering with handler over
// both UDP and TCP on the same loopback port and returns its address.
func startUpstream(t *testing.T, handler dns.HandlerFunc) netip.AddrPort {
	t.Helper()
	var (
		pc  net.PacketConn
		l   net.Listener
		err error
	)
	// UDP and TCP must share a port: the forwarder retries a truncated UDP
	// answer over TCP at the same address. Bind UDP on a random port and
	// then TCP on the same one, retrying if that port happens to be busy.
	for range 10 {
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l, err = net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			break
		}
		pc.Close()
	}
	if err != nil {
		t.Fatalf("listening on tcp: %v", err)
	}
	udp := &dns.Server{PacketConn: pc, Handler: handler}
	tcp := &dns.Server{Listener: l, Handler: handler}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() {
		udp.Shutdown()
		tcp.Shutdown()
	})
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// upstreamHandler answers A queries for names in zone with ip, TXT queries
// with a fixed text, and truncates UDP answers for names starting with "big."
// so that the forwarder has to retry over TCP.
func upstreamHandler(ip net.IP, text string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.RecursionAvailable = true
		q := r.Question[0]
		if strings.HasPrefix(q.Name, "big.") && w.RemoteAddr().Network() == "udp" {
			m.Truncated = true
			w.WriteMsg(m)
			return
		}
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: ip}}
		case dns.TypeTXT:
			m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{text}}}
		default:
			m.Rcode = dns.RcodeNameError
		}
		w.WriteMsg(m)
	}
}

func TestForward(t *testing.T) {
	corp := startUpstream(t, upstreamHandler(net.IP{10, 20, 0, 7}, "corp"))
	eng := startUpstream(t, upstreamHandler(net.IP{10, 30, 0, 7}, "eng"))
	// Nothing listens on this port; queries to it fail fast.
	dead := netip.MustParseAddrPort("127.0.0.1:1")

	ns := &nameserver{
		ip4: map[dnsname.FQDN][]net.IP{"foo.ts.net.": {{100, 64, 0, 1}}},
		forwards: map[dnsname.FQDN][]netip.AddrPort{
			"corp.internal.":     {dead, corp},
			"eng.corp.internal.": {eng},
			"down.example.":      {dead},
		},
	}
	handler := ns.handleForward()

	query := func(name string, qtype uint16) *dns.Msg {
		return &dns.Msg{
			Question: []dns.Question{{Name: name, Qtype: qtype, Qclass: dns.ClassINET}},
			MsgHdr:   dns.MsgHdr{Id: 42, RecursionDesired: true},
		}
	}
	ask := func(t *testing.T, name string, qtype uint16) *dns.Msg {
		t.Helper()
		w := &fakeResponseWriter{}
		handler(w, query(name, qtype))
		if w.msg == nil {
			t.Fatal("no response written")
		}
		if w.msg.Id != 42 {
			t.Errorf("response ID = %d, want 42", w.msg.Id)
		}
		return w.msg
	}
	wantA := func(t *testing.T, m *dns.Msg, ip net.IP) {
		t.Helper()
		if m.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
		}
		if len(m.Answer) != 1 {
			t.Fatalf("answer = %v, want one A record", m.Answer)
		}
		a, ok := m.Answer[0].(*dns.A)
		if !ok || !a.A.Equal(ip) {
			t.Fatalf("answer = %v, want A %s", m.Answer[0], ip)
		}
		if a.Hdr.Ttl != 300 {
			t.Errorf("TTL = %d, want the upstream's 300", a.Hdr.Ttl)
		}
		if !m.RecursionAvailable || !m.Authoritative {
			t.Errorf("flags RA=%v AA=%v, want the upstream's (true, true)", m.RecursionAvailable, m.Authoritative)
		}
	}

	t.Run("forwards-and-fails-over", func(t *testing.T) {
		// The first upstream for corp.internal is dead; the second answers.
		wantA(t, ask(t, "db.corp.internal.", dns.TypeA), net.IP{10, 20, 0, 7})
	})
	t.Run("domain-itself", func(t *testing.T) {
		wantA(t, ask(t, "corp.internal.", dns.TypeA), net.IP{10, 20, 0, 7})
	})
	t.Run("longest-suffix-wins", func(t *testing.T) {
		wantA(t, ask(t, "ci.eng.corp.internal.", dns.TypeA), net.IP{10, 30, 0, 7})
	})
	t.Run("case-insensitive", func(t *testing.T) {
		wantA(t, ask(t, "DB.Corp.Internal.", dns.TypeA), net.IP{10, 20, 0, 7})
	})
	t.Run("any-qtype", func(t *testing.T) {
		m := ask(t, "txt.corp.internal.", dns.TypeTXT)
		if len(m.Answer) != 1 || m.Answer[0].(*dns.TXT).Txt[0] != "corp" {
			t.Fatalf("answer = %v, want TXT corp", m.Answer)
		}
	})
	t.Run("truncated-retried-over-tcp", func(t *testing.T) {
		m := ask(t, "big.corp.internal.", dns.TypeA)
		if m.Truncated {
			t.Fatal("response is truncated: not retried over TCP")
		}
		wantA(t, m, net.IP{10, 20, 0, 7})
	})
	t.Run("all-upstreams-down", func(t *testing.T) {
		if m := ask(t, "x.down.example.", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
			t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[m.Rcode])
		}
	})
	t.Run("unknown-domain-refused", func(t *testing.T) {
		if m := ask(t, "example.com.", dns.TypeA); m.Rcode != dns.RcodeRefused {
			t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[m.Rcode])
		}
		// A parent of a forward domain is not forwarded either.
		if m := ask(t, "internal.", dns.TypeA); m.Rcode != dns.RcodeRefused {
			t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[m.Rcode])
		}
	})
	t.Run("invalid-name", func(t *testing.T) {
		if m := ask(t, "a..corp.internal.", dns.TypeA); m.Rcode != dns.RcodeFormatError {
			t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[m.Rcode])
		}
	})
}

func TestResetRecordsForwards(t *testing.T) {
	ns := &nameserver{
		configReader: func() ([]byte, error) {
			return []byte(`{"version": "v1alpha1", "ip4": {"foo.ts.net": ["100.64.0.1"]}, "forwards": {"Corp.Internal": ["10.20.0.53:53", "not-an-address", "[fd7a:115c:a1e0::53]:53"], "bad..domain": ["10.0.0.1:53"], "empty.example": ["nope"]}}`), nil
		},
	}
	if err := ns.resetRecords(); err != nil {
		t.Fatal(err)
	}
	want := map[dnsname.FQDN][]netip.AddrPort{
		"corp.internal.": {netip.MustParseAddrPort("10.20.0.53:53"), netip.MustParseAddrPort("[fd7a:115c:a1e0::53]:53")},
	}
	if len(ns.forwards) != len(want) {
		t.Fatalf("forwards = %v, want %v", ns.forwards, want)
	}
	for domain, ups := range want {
		got := ns.forwards[domain]
		if len(got) != len(ups) {
			t.Fatalf("forwards[%q] = %v, want %v", domain, got, ups)
		}
		for i := range ups {
			if got[i] != ups[i] {
				t.Errorf("forwards[%q][%d] = %v, want %v", domain, i, got[i], ups[i])
			}
		}
	}
	if len(ns.ip4) != 1 {
		t.Errorf("ip4 = %v, want the ts.net record", ns.ip4)
	}

	// A configuration without forwards clears them.
	ns.configReader = func() ([]byte, error) { return []byte(`{"version": "v1alpha1", "ip4": {}}`), nil }
	if err := ns.resetRecords(); err != nil {
		t.Fatal(err)
	}
	if len(ns.forwards) != 0 {
		t.Errorf("forwards = %v after reset, want none", ns.forwards)
	}
}
