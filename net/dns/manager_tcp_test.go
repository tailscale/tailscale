// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tstest"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
)

func mkDNSRequest(domain dnsname.FQDN, tp dns.Type, modify func(*dns.Builder)) []byte {
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

	if err := builder.StartAdditionals(); err != nil {
		panic(err)
	}

	if modify != nil {
		modify(&builder)
	}
	payload, _ := builder.Finish()

	return payload
}

func addEDNS(builder *dns.Builder) {
	ednsHeader := dns.ResourceHeader{
		Name:  dns.MustNewName("."),
		Type:  dns.TypeOPT,
		Class: dns.Class(4095),
	}

	if err := builder.OPTResource(ednsHeader, dns.OPTResource{}); err != nil {
		panic(err)
	}
}

func mkLargeDNSRequest(domain dnsname.FQDN, tp dns.Type) []byte {
	return mkDNSRequest(domain, tp, func(builder *dns.Builder) {
		ednsHeader := dns.ResourceHeader{
			Name:  dns.MustNewName("."),
			Type:  dns.TypeOPT,
			Class: dns.Class(4095),
		}

		if err := builder.OPTResource(ednsHeader, dns.OPTResource{
			Options: []dns.Option{{
				Code: 1234,
				Data: bytes.Repeat([]byte("A"), maxReqSizeTCP),
			}},
		}); err != nil {
			panic(err)
		}
	})
}

func TestDNSOverTCP(t *testing.T) {
	f := fakeOSConfigurator{
		SplitDNS: true,
		BaseConfig: OSConfig{
			Nameservers:   mustIPs("8.8.8.8"),
			SearchDomains: fqdns("coffee.shop"),
		},
	}
	bus := eventbustest.NewBus(t)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	cknobs := &controlknobs.Knobs{}
	m := NewManager(t.Logf, &f, health.NewTracker(bus), dialer, nil, cknobs, "", bus)
	m.resolver.TestOnlySetHook(f.SetResolver)
	m.Set(Config{
		Hosts: hosts(
			"dave.ts.com.", "1.2.3.4",
			"bradfitz.ts.com.", "2.3.4.5"),
		Routes:        upstreams("ts.com", ""),
		SearchDomains: fqdns("tailscale.com", "universe.tf"),
	})
	defer m.Down()

	c, s := net.Pipe()
	defer s.Close()
	go m.HandleTCPConn(s, netip.AddrPort{})
	defer c.Close()

	wantResults := map[dnsname.FQDN]string{
		"dave.ts.com.":     "1.2.3.4",
		"bradfitz.ts.com.": "2.3.4.5",
	}

	for domain := range wantResults {
		b := mkDNSRequest(domain, dns.TypeA, addEDNS)
		binary.Write(c, binary.BigEndian, uint16(len(b)))
		c.Write(b)
	}

	results := map[dnsname.FQDN]string{}
	for range len(wantResults) {
		var respLength uint16
		if err := binary.Read(c, binary.BigEndian, &respLength); err != nil {
			t.Fatalf("reading len: %v", err)
		}
		resp := make([]byte, int(respLength))
		if _, err := io.ReadFull(c, resp); err != nil {
			t.Fatalf("reading data: %v", err)
		}

		var parser dns.Parser
		if _, err := parser.Start(resp); err != nil {
			t.Errorf("parser.Start() failed: %v", err)
			continue
		}
		q, err := parser.Question()
		if err != nil {
			t.Errorf("parser.Question(): %v", err)
			continue
		}
		if err := parser.SkipAllQuestions(); err != nil {
			t.Errorf("parser.SkipAllQuestions(): %v", err)
			continue
		}
		ah, err := parser.AnswerHeader()
		if err != nil {
			t.Errorf("parser.AnswerHeader(): %v", err)
			continue
		}
		if ah.Type != dns.TypeA {
			t.Errorf("unexpected answer type: got %v, want %v", ah.Type, dns.TypeA)
			continue
		}
		res, err := parser.AResource()
		if err != nil {
			t.Errorf("parser.AResource(): %v", err)
			continue
		}
		results[dnsname.FQDN(q.Name.String())] = net.IP(res.A[:]).String()
	}
	c.Close()

	if diff := cmp.Diff(wantResults, results); diff != "" {
		t.Errorf("wrong results (-got+want)\n%s", diff)
	}
}

func TestDNSOverTCP_TooLarge(t *testing.T) {
	log := tstest.WhileTestRunningLogger(t)

	f := fakeOSConfigurator{
		SplitDNS: true,
		BaseConfig: OSConfig{
			Nameservers:   mustIPs("8.8.8.8"),
			SearchDomains: fqdns("coffee.shop"),
		},
	}
	bus := eventbustest.NewBus(t)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	m := NewManager(log, &f, health.NewTracker(bus), dialer, nil, nil, "", bus)
	m.resolver.TestOnlySetHook(f.SetResolver)
	m.Set(Config{
		Hosts:         hosts("andrew.ts.com.", "1.2.3.4"),
		Routes:        upstreams("ts.com", ""),
		SearchDomains: fqdns("tailscale.com"),
	})
	defer m.Down()

	c, s := net.Pipe()
	defer s.Close()
	go m.HandleTCPConn(s, netip.AddrPort{})
	defer c.Close()

	var b []byte
	domain := dnsname.FQDN("andrew.ts.com.")

	// Write a successful request, then a large one that will fail; this
	// exercises the data race in tailscale/tailscale#6725
	b = mkDNSRequest(domain, dns.TypeA, addEDNS)
	binary.Write(c, binary.BigEndian, uint16(len(b)))
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}

	c.SetWriteDeadline(time.Now().Add(5 * time.Second))

	b = mkLargeDNSRequest(domain, dns.TypeA)
	if err := binary.Write(c, binary.BigEndian, uint16(len(b))); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(b); err != nil {
		// It's possible that we get an error here, since the
		// net.Pipe() implementation enforces synchronous reads. So,
		// handleReads could read the size, then error, and this write
		// fails. That's actually a success for this test!
		if errors.Is(err, io.ErrClosedPipe) {
			t.Logf("pipe (correctly) closed when writing large response")
			return
		}

		t.Fatal(err)
	}

	t.Logf("reading responses")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))

	// We expect an EOF now, since the connection will have been closed due
	// to a too-large query.
	var respLength uint16
	err := binary.Read(c, binary.BigEndian, &respLength)
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("expected EOF on large read; got %v", err)
	}
}
