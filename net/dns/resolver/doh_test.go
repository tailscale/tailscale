// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"context"
	"flag"
	"net/http"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/dns/publicdns"
)

var testDoH = flag.Bool("test-doh", false, "do real DoH tests against the network")

const someDNSID = 123 // something non-zero as a test; in violation of spec's SHOULD of 0

func someDNSQuestion(t testing.TB) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		OpCode:           0, // query
		RecursionDesired: true,
		ID:               someDNSID,
	})
	b.StartQuestions() // err
	b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("tailscale.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestDoH(t *testing.T) {
	if !*testDoH {
		t.Skip("skipping manual test without --test-doh flag")
	}
	if len(publicdns.KnownDoH()) == 0 {
		t.Fatal("no known DoH")
	}

	f := &forwarder{
		dohSem: make(chan struct{}, 10),
	}

	for urlBase := range publicdns.DoHIPsOfBase() {
		t.Run(urlBase, func(t *testing.T) {
			c, ok := f.getKnownDoHClientForProvider(urlBase)
			if !ok {
				t.Fatal("expected DoH")
			}
			res, err := f.sendDoH(context.Background(), urlBase, c, someDNSQuestion(t))
			if err != nil {
				t.Fatal(err)
			}
			c.Transport.(*http.Transport).CloseIdleConnections()

			var p dnsmessage.Parser
			h, err := p.Start(res)
			if err != nil {
				t.Fatal(err)
			}
			if h.ID != someDNSID {
				t.Errorf("response DNS ID = %v; want %v", h.ID, someDNSID)
			}

			p.SkipAllQuestions()
			aa, err := p.AllAnswers()
			if err != nil {
				t.Fatal(err)
			}
			if len(aa) == 0 {
				t.Fatal("no answers")
			}
			for _, r := range aa {
				t.Logf("got: %v", r.GoString())
			}
		})
	}
}

func TestDoHV6Fallback(t *testing.T) {
	for ip, base := range publicdns.KnownDoH() {
		if ip.Is4() {
			ip6, ok := publicdns.DoHV6(base)
			if !ok {
				t.Errorf("no v6 DoH known for %v", ip)
			} else if !ip6.Is6() {
				t.Errorf("dohV6(%q) returned non-v6 address %v", base, ip6)
			}
		}
	}
}
