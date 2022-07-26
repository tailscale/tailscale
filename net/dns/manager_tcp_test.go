// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/tsdial"
	"tailscale.com/util/dnsname"
)

func mkDNSRequest(domain dnsname.FQDN, tp dns.Type) []byte {
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

	ednsHeader := dns.ResourceHeader{
		Name:  dns.MustNewName("."),
		Type:  dns.TypeOPT,
		Class: dns.Class(4095),
	}

	if err := builder.OPTResource(ednsHeader, dns.OPTResource{}); err != nil {
		panic(err)
	}

	payload, _ := builder.Finish()

	return payload
}

func TestDNSOverTCP(t *testing.T) {
	f := fakeOSConfigurator{
		SplitDNS: true,
		BaseConfig: OSConfig{
			Nameservers:   mustIPs("8.8.8.8"),
			SearchDomains: fqdns("coffee.shop"),
		},
	}
	m := NewManager(t.Logf, &f, nil, new(tsdial.Dialer), nil)
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

	for domain, _ := range wantResults {
		b := mkDNSRequest(domain, dns.TypeA)
		binary.Write(c, binary.BigEndian, uint16(len(b)))
		c.Write(b)
	}

	results := map[dnsname.FQDN]string{}
	for i := 0; i < len(wantResults); i++ {
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
