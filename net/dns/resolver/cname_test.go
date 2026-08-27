// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
)

func TestQueryCompletesLocalCNAME(t *testing.T) {
	const (
		alias  dnsname.FQDN = "service.example.com."
		target dnsname.FQDN = "service.example-tailnet.ts.net."
	)
	targetIP := netip.MustParseAddr("100.100.100.101")
	query := dnspacket(alias, dns.TypeA, noEdns)
	upstream := makeCNAMEOnlyResponse(t, alias, target, dns.TypeA, dns.RCodeNameError)

	var upstreamQueries atomic.Int64
	port := runDNSServer(t, nil, upstream, func(_ bool, _ []byte) {
		upstreamQueries.Add(1)
	})

	r := newResolver(t)
	defer r.Close()
	r.SetConfig(Config{
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			".": {{Addr: fmt.Sprintf("127.0.0.1:%d", port)}},
		},
		LocalDomains: []dnsname.FQDN{"example-tailnet.ts.net."},
	})
	r.SetMagicDNSHosts(fakeMagicDNSHosts{
		hosts: map[dnsname.FQDN][]netip.Addr{
			target: {targetIP},
		},
	})

	got, err := syncRespond(r, query)
	if err != nil {
		t.Fatal(err)
	}
	if gotQueries := upstreamQueries.Load(); gotQueries != 1 {
		t.Fatalf("upstream queries = %d, want 1", gotQueries)
	}

	var p dns.Parser
	h, err := p.Start(got)
	if err != nil {
		t.Fatal(err)
	}
	if h.RCode != dns.RCodeSuccess {
		t.Fatalf("response code = %v, want %v", h.RCode, dns.RCodeSuccess)
	}
	questions, err := p.AllQuestions()
	if err != nil {
		t.Fatal(err)
	}
	if len(questions) != 1 {
		t.Fatalf("questions = %d, want 1", len(questions))
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 2 {
		t.Fatalf("answers = %d, want CNAME and A", len(answers))
	}
	cname, ok := answers[0].Body.(*dns.CNAMEResource)
	if !ok {
		t.Fatalf("first answer = %T, want CNAME", answers[0].Body)
	}
	if gotTarget := cname.CNAME.String(); gotTarget != target.WithTrailingDot() {
		t.Errorf("CNAME target = %q, want %q", gotTarget, target)
	}
	a, ok := answers[1].Body.(*dns.AResource)
	if !ok {
		t.Fatalf("second answer = %T, want A", answers[1].Body)
	}
	if gotIP := netip.AddrFrom4(a.A); gotIP != targetIP {
		t.Errorf("terminal address = %v, want %v", gotIP, targetIP)
	}
}

func makeCNAMEOnlyResponse(t testing.TB, alias, target dnsname.FQDN, typ dns.Type, rcode dns.RCode) []byte {
	t.Helper()
	aliasName := dns.MustNewName(alias.WithTrailingDot())
	targetName := dns.MustNewName(target.WithTrailingDot())
	b := dns.NewBuilder(nil, dns.Header{
		Response:           true,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dns.Question{
		Name:  aliasName,
		Type:  typ,
		Class: dns.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := b.CNAMEResource(dns.ResourceHeader{
		Name:  aliasName,
		Type:  dns.TypeCNAME,
		Class: dns.ClassINET,
		TTL:   300,
	}, dns.CNAMEResource{CNAME: targetName}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAuthorities(); err != nil {
		t.Fatal(err)
	}
	if err := marshalSOA("ts.net.", &b); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMaybeCompleteCNAMEResponse(t *testing.T) {
	const target = "target.example-tailnet.ts.net."
	targetIP := netip.MustParseAddr("100.64.0.99")
	r := &Resolver{
		hostToIP: map[dnsname.FQDN][]netip.Addr{
			target: {targetIP},
		},
	}
	queryQuestion := cnameTestQuestion("Service.Example.COM.", dns.TypeA)
	query := makeCNAMETestMessage(t, cnameTestMessage{
		header: dns.Header{
			ID:               42,
			RecursionDesired: true,
			CheckingDisabled: true,
		},
		questions: []dns.Question{queryQuestion},
		opts:      []cnameTestOPT{{payload: 1232, dnssecOK: true}},
	})
	upstream := makeCNAMETestMessage(t, cnameTestMessage{
		header: dns.Header{
			ID:                 42,
			Response:           true,
			Authoritative:      true,
			RecursionAvailable: true,
			AuthenticData:      true,
			RCode:              dns.RCodeNameError,
		},
		questions: []dns.Question{cnameTestQuestion("SERVICE.example.com.", dns.TypeA)},
		// Deliberately out of order and with mixed case.
		edges: []cnameTestEdge{
			{owner: "Middle.Example.NET.", target: "TARGET.example-tailnet.ts.net.", ttl: 20},
			{owner: "SERVICE.example.com.", target: "MIDDLE.example.net.", ttl: 10},
		},
		authorityTypes: []dns.Type{dns.TypeSOA},
		opts:           []cnameTestOPT{{payload: 1232}},
	})

	got, changed := r.maybeCompleteCNAMEResponse(query, upstream)
	if !changed {
		t.Fatal("response was not completed")
	}
	var p dns.Parser
	h, err := p.Start(got)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Response || h.RCode != dns.RCodeSuccess {
		t.Errorf("header response/rcode = %v/%v, want true/NOERROR", h.Response, h.RCode)
	}
	if h.ID != 42 {
		t.Errorf("header ID = %d, want 42", h.ID)
	}
	if !h.RecursionDesired || !h.RecursionAvailable || !h.CheckingDisabled {
		t.Errorf("header did not preserve RD/RA/CD: %+v", h)
	}
	if h.Authoritative || h.AuthenticData || h.Truncated {
		t.Errorf("header retained synthesized-invalid AA/AD/TC bits: %+v", h)
	}
	questions, err := p.AllQuestions()
	if err != nil {
		t.Fatal(err)
	}
	if len(questions) != 1 || questions[0] != queryQuestion {
		t.Errorf("questions = %+v, want original query question %+v", questions, queryQuestion)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 3 {
		t.Fatalf("answers = %d, want two CNAMEs and A", len(answers))
	}
	first, ok := answers[0].Body.(*dns.CNAMEResource)
	if !ok {
		t.Fatalf("answer 0 = %T, want CNAME", answers[0].Body)
	}
	if got, want := answers[0].Header.Name.String(), "SERVICE.example.com."; got != want {
		t.Errorf("CNAME 0 owner = %q, want %q", got, want)
	}
	if got, want := first.CNAME.String(), "MIDDLE.example.net."; got != want {
		t.Errorf("CNAME 0 target = %q, want %q", got, want)
	}
	if got, want := answers[0].Header.TTL, uint32(10); got != want {
		t.Errorf("CNAME 0 TTL = %d, want %d", got, want)
	}
	second, ok := answers[1].Body.(*dns.CNAMEResource)
	if !ok {
		t.Fatalf("answer 1 = %T, want CNAME", answers[1].Body)
	}
	if got, want := second.CNAME.String(), "TARGET.example-tailnet.ts.net."; got != want {
		t.Errorf("CNAME 1 target = %q, want %q", got, want)
	}
	if got, want := answers[1].Header.TTL, uint32(20); got != want {
		t.Errorf("CNAME 1 TTL = %d, want %d", got, want)
	}
	a, ok := answers[2].Body.(*dns.AResource)
	if !ok {
		t.Fatalf("answer 2 = %T, want A", answers[2].Body)
	}
	if got := netip.AddrFrom4(a.A); got != targetIP {
		t.Errorf("terminal address = %v, want %v", got, targetIP)
	}
	if got, want := answers[2].Header.Name.String(), "TARGET.example-tailnet.ts.net."; got != want {
		t.Errorf("terminal owner = %q, want %q", got, want)
	}
	if got, want := answers[2].Header.TTL, uint32(defaultTTL/time.Second); got != want {
		t.Errorf("terminal TTL = %d, want %d", got, want)
	}
	authorities, err := p.AllAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	if len(authorities) != 0 {
		t.Errorf("authorities = %d, want 0", len(authorities))
	}
	additionals, err := p.AllAdditionals()
	if err != nil {
		t.Fatal(err)
	}
	if len(additionals) != 1 {
		t.Fatalf("additionals = %d, want one OPT", len(additionals))
	}
	opt, ok := additionals[0].Body.(*dns.OPTResource)
	if !ok {
		t.Fatalf("additional = %T, want OPT", additionals[0].Body)
	}
	if got, want := additionals[0].Header.Class, dns.Class(maxResponseBytes); got != want {
		t.Errorf("OPT payload size = %d, want %d", got, want)
	}
	if !additionals[0].Header.DNSSECAllowed() || additionals[0].Header.TTL != ednsDNSSECOK {
		t.Errorf("OPT flags = %#x, want only DO", additionals[0].Header.TTL)
	}
	if len(opt.Options) != 0 {
		t.Errorf("OPT options = %v, want none", opt.Options)
	}
}

func TestMaybeCompleteCNAMEResponseAAAA(t *testing.T) {
	const (
		alias  = "service.example.com."
		target = "service.example-tailnet.ts.net."
	)
	targetIP := netip.MustParseAddr("fd7a:115c:a1e0::1234")
	r := &Resolver{
		hostToIP: map[dnsname.FQDN][]netip.Addr{
			target: {netip.MustParseAddr("100.64.0.1"), targetIP},
		},
	}
	q := cnameTestQuestion(alias, dns.TypeAAAA)
	query := makeCNAMETestMessage(t, cnameTestMessage{
		header:    dns.Header{ID: 7},
		questions: []dns.Question{q},
	})
	upstream := makeCNAMETestMessage(t, cnameTestMessage{
		header: dns.Header{
			ID:       7,
			Response: true,
			RCode:    dns.RCodeSuccess,
		},
		questions: []dns.Question{q},
		edges:     []cnameTestEdge{{owner: alias, target: target, ttl: 60}},
	})
	got, changed := r.maybeCompleteCNAMEResponse(query, upstream)
	if !changed {
		t.Fatal("response was not completed")
	}
	var p dns.Parser
	if _, err := p.Start(got); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 2 {
		t.Fatalf("answers = %d, want CNAME and AAAA", len(answers))
	}
	aaaa, ok := answers[1].Body.(*dns.AAAAResource)
	if !ok {
		t.Fatalf("terminal answer = %T, want AAAA", answers[1].Body)
	}
	if got := netip.AddrFrom16(aaaa.AAAA); got != targetIP {
		t.Errorf("terminal address = %v, want %v", got, targetIP)
	}
}

func TestMaybeCompleteCNAMEResponseNoData(t *testing.T) {
	const (
		alias  = "service.example.com."
		target = "service.example-tailnet.ts.net."
	)
	r := &Resolver{
		hostToIP: map[dnsname.FQDN][]netip.Addr{
			target: {netip.MustParseAddr("100.64.0.1")},
		},
	}
	q := cnameTestQuestion(alias, dns.TypeAAAA)
	query := makeCNAMETestMessage(t, cnameTestMessage{
		header:    dns.Header{ID: 71},
		questions: []dns.Question{q},
	})
	upstream := makeCNAMETestMessage(t, cnameTestMessage{
		header:         dns.Header{ID: 71, Response: true, RCode: dns.RCodeNameError},
		questions:      []dns.Question{q},
		edges:          []cnameTestEdge{{owner: alias, target: target, ttl: 60}},
		authorityTypes: []dns.Type{dns.TypeSOA},
	})
	got, changed := r.maybeCompleteCNAMEResponse(query, upstream)
	if !changed {
		t.Fatal("known wrong-family target was not changed to NODATA")
	}
	var p dns.Parser
	h, err := p.Start(got)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 71 || h.RCode != dns.RCodeSuccess {
		t.Errorf("header = %+v, want ID 71 and NOERROR", h)
	}
	if _, err := p.AllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 || answers[0].Header.Type != dns.TypeCNAME {
		t.Fatalf("answers = %+v, want only the preserved CNAME", answers)
	}
	authorities, err := p.AllAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	if len(authorities) != 0 {
		t.Errorf("authorities = %d, want none", len(authorities))
	}
}

func TestMaybeCompleteCNAMEResponseRejectsTrailingBytes(t *testing.T) {
	const (
		alias  = "service.example.com."
		target = "service.example-tailnet.ts.net."
	)
	r := &Resolver{
		hostToIP: map[dnsname.FQDN][]netip.Addr{
			target: {netip.MustParseAddr("100.64.0.1")},
		},
	}
	q := cnameTestQuestion(alias, dns.TypeA)
	query := makeCNAMETestMessage(t, cnameTestMessage{
		header:    dns.Header{ID: 8},
		questions: []dns.Question{q},
	})
	upstream := makeCNAMETestMessage(t, cnameTestMessage{
		header:    dns.Header{ID: 8, Response: true, RCode: dns.RCodeNameError},
		questions: []dns.Question{q},
		edges:     []cnameTestEdge{{owner: alias, target: target, ttl: 60}},
	})
	tests := []struct {
		name     string
		query    []byte
		upstream []byte
	}{
		{"query", append(bytes.Clone(query), 0xde, 0xad), upstream},
		{"response", query, append(bytes.Clone(upstream), 0xbe, 0xef)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := r.maybeCompleteCNAMEResponse(tt.query, tt.upstream)
			if changed {
				t.Fatal("response with undeclared trailing bytes was changed")
			}
			if !bytes.Equal(got, tt.upstream) {
				t.Errorf("passthrough mismatch\ngot:  %x\nwant: %x", got, tt.upstream)
			}
		})
	}
}

func TestMaybeCompleteCNAMEResponsePassthrough(t *testing.T) {
	const (
		alias  = "service.example.com."
		target = "service.example-tailnet.ts.net."
	)
	targetIP := netip.MustParseAddr("100.64.0.1")
	targetResolver := &Resolver{
		hostToIP: map[dnsname.FQDN][]netip.Addr{
			target: {targetIP},
		},
	}
	emptyResolver := &Resolver{hostToIP: map[dnsname.FQDN][]netip.Addr{}}

	q := cnameTestQuestion(alias, dns.TypeA)
	baseQuery := makeCNAMETestMessage(t, cnameTestMessage{
		header:    dns.Header{ID: 9},
		questions: []dns.Question{q},
	})
	responseWithoutAuthority := makeCNAMETestMessage(t, cnameTestMessage{
		header:    dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError},
		questions: []dns.Question{q},
		edges:     []cnameTestEdge{{owner: alias, target: target, ttl: 60}},
	})
	baseResponse := makeCNAMETestMessage(t, cnameTestMessage{
		header:         dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError},
		questions:      []dns.Question{q},
		edges:          []cnameTestEdge{{owner: alias, target: target, ttl: 60}},
		authorityTypes: []dns.Type{dns.TypeSOA},
	})
	response := func(header dns.Header, question dns.Question, edges []cnameTestEdge) []byte {
		return makeCNAMETestMessage(t, cnameTestMessage{
			header:         header,
			questions:      []dns.Question{question},
			edges:          edges,
			authorityTypes: []dns.Type{dns.TypeSOA},
		})
	}
	edge := []cnameTestEdge{{owner: alias, target: target, ttl: 60}}

	symbolicResolver := &Resolver{
		hostToIP: map[dnsname.FQDN][]netip.Addr{
			dnsSymbolicFQDN: {targetIP},
		},
	}
	viaTarget := dnsname.FQDN("1-2-3-4-via-1.")
	viaResolver := &Resolver{
		hostToIP: map[dnsname.FQDN][]netip.Addr{
			viaTarget: {targetIP},
		},
	}
	onionTarget := dnsname.FQDN("hidden.onion.")
	onionResolver := &Resolver{
		hostToIP: map[dnsname.FQDN][]netip.Addr{
			onionTarget: {targetIP},
		},
	}

	tests := []struct {
		name     string
		resolver *Resolver
		query    []byte
		upstream []byte
	}{
		{"malformed_query", targetResolver, []byte{0}, baseResponse},
		{"malformed_response", targetResolver, baseQuery, baseResponse[:len(baseResponse)-1]},
		{"query_reserved_z", targetResolver, setCNAMEHeaderZ(baseQuery), baseResponse},
		{"response_reserved_z", targetResolver, baseQuery, setCNAMEHeaderZ(baseResponse)},
		{"short_cname_rdlength", targetResolver, baseQuery, adjustCNAMETestRDataLength(t, responseWithoutAuthority, dns.TypeCNAME, -1)},
		{"padded_cname_rdlength", targetResolver, baseQuery, adjustCNAMETestRDataLength(t, responseWithoutAuthority, dns.TypeCNAME, 1)},
		{"short_soa_rdlength", targetResolver, baseQuery, adjustCNAMETestRDataLength(t, baseResponse, dns.TypeSOA, -1)},
		{"padded_soa_rdlength", targetResolver, baseQuery, adjustCNAMETestRDataLength(t, baseResponse, dns.TypeSOA, 1)},
		{"wrong_id", targetResolver, baseQuery, response(dns.Header{ID: 10, Response: true, RCode: dns.RCodeNameError}, q, edge)},
		{"response_opcode", targetResolver, baseQuery, response(dns.Header{ID: 9, Response: true, OpCode: 1, RCode: dns.RCodeNameError}, q, edge)},
		{"truncated", targetResolver, baseQuery, response(dns.Header{ID: 9, Response: true, Truncated: true, RCode: dns.RCodeNameError}, q, edge)},
		{"servfail", targetResolver, baseQuery, response(dns.Header{ID: 9, Response: true, RCode: dns.RCodeServerFailure}, q, edge)},
		{"wrong_response_question", targetResolver, baseQuery, response(dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError}, cnameTestQuestion("other.example.com.", dns.TypeA), edge)},
		{
			"unsupported_query_type",
			targetResolver,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:    dns.Header{ID: 9},
				questions: []dns.Question{cnameTestQuestion(alias, dns.TypeMX)},
			}),
			response(dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError}, cnameTestQuestion(alias, dns.TypeMX), edge),
		},
		{
			"unsupported_query_class",
			targetResolver,
			makeCNAMETestMessage(t, cnameTestMessage{
				header: dns.Header{ID: 9},
				questions: []dns.Question{{
					Name:  dns.MustNewName(alias),
					Type:  dns.TypeA,
					Class: dns.ClassCHAOS,
				}},
			}),
			baseResponse,
		},
		{
			"query_opt_with_option",
			targetResolver,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:    dns.Header{ID: 9},
				questions: []dns.Question{q},
				opts: []cnameTestOPT{{
					payload: 1232,
					options: []dns.Option{{Code: 15, Data: []byte{0}}},
				}},
			}),
			baseResponse,
		},
		{
			"no_cname",
			targetResolver,
			baseQuery,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:         dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError},
				questions:      []dns.Question{q},
				authorityTypes: []dns.Type{dns.TypeSOA},
			}),
		},
		{
			"non_cname_answer",
			targetResolver,
			baseQuery,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:         dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError},
				questions:      []dns.Question{q},
				answerType:     dns.TypeTXT,
				authorityTypes: []dns.Type{dns.TypeSOA},
			}),
		},
		{
			"already_complete",
			targetResolver,
			baseQuery,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:        dns.Header{ID: 9, Response: true},
				questions:     []dns.Question{q},
				edges:         edge,
				terminalOwner: target,
				terminalIP:    targetIP,
			}),
		},
		{
			"duplicate_owner",
			targetResolver,
			baseQuery,
			response(dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError}, q, []cnameTestEdge{
				{owner: alias, target: target, ttl: 60},
				{owner: alias, target: "other.example-tailnet.ts.net.", ttl: 60},
			}),
		},
		{
			"loop",
			targetResolver,
			baseQuery,
			response(dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError}, q, []cnameTestEdge{
				{owner: alias, target: "middle.example.com.", ttl: 60},
				{owner: "middle.example.com.", target: alias, ttl: 60},
			}),
		},
		{
			"disconnected",
			targetResolver,
			baseQuery,
			response(dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError}, q, []cnameTestEdge{
				{owner: alias, target: target, ttl: 60},
				{owner: "unrelated.example.com.", target: "other.example.com.", ttl: 60},
			}),
		},
		{"unknown_terminal", emptyResolver, baseQuery, baseResponse},
		{
			"symbolic_terminal",
			symbolicResolver,
			baseQuery,
			response(dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError}, q, []cnameTestEdge{{owner: alias, target: string(dnsSymbolicFQDN), ttl: 60}}),
		},
		{
			"4via6_terminal",
			viaResolver,
			baseQuery,
			response(dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError}, q, []cnameTestEdge{{owner: alias, target: string(viaTarget), ttl: 60}}),
		},
		{
			"onion_terminal",
			onionResolver,
			baseQuery,
			response(dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError}, q, []cnameTestEdge{{owner: alias, target: string(onionTarget), ttl: 60}}),
		},
		{
			"dnssec_answer",
			targetResolver,
			baseQuery,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:         dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError},
				questions:      []dns.Question{q},
				edges:          edge,
				answerType:     dns.Type(46), // RRSIG
				authorityTypes: []dns.Type{dns.TypeSOA},
			}),
		},
		{
			"two_soa_records",
			targetResolver,
			baseQuery,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:         dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError},
				questions:      []dns.Question{q},
				edges:          edge,
				authorityTypes: []dns.Type{dns.TypeSOA, dns.TypeSOA},
			}),
		},
		{
			"non_soa_authority",
			targetResolver,
			baseQuery,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:         dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError},
				questions:      []dns.Question{q},
				edges:          edge,
				authorityTypes: []dns.Type{dns.Type(47)}, // NSEC
			}),
		},
		{
			"response_opt_with_option",
			targetResolver,
			baseQuery,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:         dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError},
				questions:      []dns.Question{q},
				edges:          edge,
				authorityTypes: []dns.Type{dns.TypeSOA},
				opts: []cnameTestOPT{{
					payload: 1232,
					options: []dns.Option{{Code: 15, Data: []byte{0}}},
				}},
			}),
		},
		{
			"response_opt_bad_version",
			targetResolver,
			baseQuery,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:         dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError},
				questions:      []dns.Question{q},
				edges:          edge,
				authorityTypes: []dns.Type{dns.TypeSOA},
				opts:           []cnameTestOPT{{payload: 1232, extraTTL: 1 << 16}},
			}),
		},
		{
			"unsupported_additional",
			targetResolver,
			baseQuery,
			makeCNAMETestMessage(t, cnameTestMessage{
				header:         dns.Header{ID: 9, Response: true, RCode: dns.RCodeNameError},
				questions:      []dns.Question{q},
				edges:          edge,
				authorityTypes: []dns.Type{dns.TypeSOA},
				additionalType: dns.TypeTXT,
			}),
		},
		{
			"oversized_response",
			targetResolver,
			baseQuery,
			append(bytes.Clone(baseResponse), make([]byte, maxResponseBytes-len(baseResponse)+1)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := tt.resolver.maybeCompleteCNAMEResponse(tt.query, tt.upstream)
			if changed {
				t.Fatal("changed = true, want byte-exact passthrough")
			}
			if !bytes.Equal(got, tt.upstream) {
				t.Errorf("passthrough mismatch\ngot:  %x\nwant: %x", got, tt.upstream)
			}
		})
	}
}

func TestCompletedCNAMEResponseUDPTruncation(t *testing.T) {
	const alias = "service.example.com."
	q := cnameTestQuestion(alias, dns.TypeA)
	query := makeCNAMETestMessage(t, cnameTestMessage{
		header:    dns.Header{ID: 12},
		questions: []dns.Question{q},
	})

	for hops := 1; hops <= 40; hops++ {
		for terminalLabelLen := 1; terminalLabelLen <= 63; terminalLabelLen++ {
			names := make([]string, hops+1)
			names[0] = alias
			for i := 1; i < hops; i++ {
				names[i] = fmt.Sprintf("hop-%02d.example.net.", i)
			}
			names[hops] = strings.Repeat("x", terminalLabelLen) + ".example-tailnet.ts.net."
			edges := make([]cnameTestEdge, hops)
			for i := range edges {
				edges[i] = cnameTestEdge{owner: names[i], target: names[i+1], ttl: 60}
			}
			upstream := makeCNAMETestMessage(t, cnameTestMessage{
				header:    dns.Header{ID: 12, Response: true, RCode: dns.RCodeNameError},
				questions: []dns.Question{q},
				edges:     edges,
			})
			if len(upstream) > 512 {
				continue
			}
			r := &Resolver{
				hostToIP: map[dnsname.FQDN][]netip.Addr{
					dnsname.FQDN(names[hops]): {netip.MustParseAddr("100.64.0.1")},
				},
			}
			completed, changed := r.maybeCompleteCNAMEResponse(query, upstream)
			if !changed || len(completed) <= 512 {
				continue
			}

			udp := checkResponseSizeAndSetTC(bytes.Clone(completed), query, "udp", t.Logf)
			var p dns.Parser
			h, err := p.Start(udp)
			if err != nil {
				t.Fatal(err)
			}
			if !h.Truncated {
				t.Fatalf("completed %d-byte UDP response did not set TC", len(completed))
			}
			tcp := checkResponseSizeAndSetTC(bytes.Clone(completed), query, "tcp", t.Logf)
			if h, err := p.Start(tcp); err != nil || h.Truncated {
				t.Fatalf("TCP response unexpectedly truncated: header=%+v, err=%v", h, err)
			}
			return
		}
	}
	t.Fatal("could not construct completion that crosses the 512-byte UDP boundary")
}

func TestLookupLocalHost(t *testing.T) {
	configIP := netip.MustParseAddr("100.64.0.1")
	magicIP := netip.MustParseAddr("100.64.0.2")
	configSubdomainIP := netip.MustParseAddr("100.64.0.3")
	magicSubdomainIP := netip.MustParseAddr("100.64.0.4")
	r := newResolver(t)
	defer r.Close()
	r.SetConfig(Config{
		Hosts: map[dnsname.FQDN][]netip.Addr{
			"config.example-tailnet.ts.net.":     {configIP},
			"both.example-tailnet.ts.net.":       {configIP},
			"config-sub.example-tailnet.ts.net.": {configSubdomainIP},
		},
		SubdomainHosts: set.Of[dnsname.FQDN]("config-sub.example-tailnet.ts.net."),
	})
	r.SetMagicDNSHosts(fakeMagicDNSHosts{
		hosts: map[dnsname.FQDN][]netip.Addr{
			"magic.example-tailnet.ts.net.":     {magicIP},
			"both.example-tailnet.ts.net.":      {magicIP},
			"magic-sub.example-tailnet.ts.net.": {magicSubdomainIP},
		},
		subdomain: set.Of[dnsname.FQDN]("magic-sub.example-tailnet.ts.net."),
	})

	tests := []struct {
		name  string
		query dnsname.FQDN
		want  []netip.Addr
		found bool
	}{
		{"config", "config.example-tailnet.ts.net.", []netip.Addr{configIP}, true},
		{"magic", "magic.example-tailnet.ts.net.", []netip.Addr{magicIP}, true},
		{"config_precedence", "both.example-tailnet.ts.net.", []netip.Addr{configIP}, true},
		{"config_subdomain", "deep.config-sub.example-tailnet.ts.net.", []netip.Addr{configSubdomainIP}, true},
		{"magic_subdomain", "deep.magic-sub.example-tailnet.ts.net.", []netip.Addr{magicSubdomainIP}, true},
		{"missing", "missing.example-tailnet.ts.net.", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := r.lookupLocalHost(tt.query)
			if found != tt.found || !slices.Equal(got, tt.want) {
				t.Errorf("lookupLocalHost(%q) = (%v, %v), want (%v, %v)", tt.query, got, found, tt.want, tt.found)
			}
		})
	}
}

func FuzzMaybeCompleteCNAMEResponse(f *testing.F) {
	const (
		alias  = "service.example.com."
		target = "service.example-tailnet.ts.net."
	)
	q := cnameTestQuestion(alias, dns.TypeA)
	query := makeCNAMETestMessage(f, cnameTestMessage{
		header:    dns.Header{ID: 11},
		questions: []dns.Question{q},
		opts:      []cnameTestOPT{{payload: 1232, dnssecOK: true}},
	})
	response := makeCNAMETestMessage(f, cnameTestMessage{
		header:         dns.Header{ID: 11, Response: true, RCode: dns.RCodeNameError},
		questions:      []dns.Question{q},
		edges:          []cnameTestEdge{{owner: alias, target: target, ttl: 60}},
		authorityTypes: []dns.Type{dns.TypeSOA},
		opts:           []cnameTestOPT{{payload: 1232}},
	})
	f.Add(query, response)
	f.Add([]byte{}, []byte{})
	f.Add(query, append(bytes.Clone(response), 0xde, 0xad))

	r := &Resolver{
		hostToIP: map[dnsname.FQDN][]netip.Addr{
			target: {netip.MustParseAddr("100.64.0.1")},
		},
	}
	f.Fuzz(func(t *testing.T, query, upstream []byte) {
		got, changed := r.maybeCompleteCNAMEResponse(query, upstream)
		if !changed {
			if !bytes.Equal(got, upstream) {
				t.Fatal("unchanged result was not byte-exact")
			}
			return
		}
		if len(got) > maxResponseBytes {
			t.Fatalf("changed response is %d bytes, want at most %d", len(got), maxResponseBytes)
		}
		queryHeader, queryQuestion, queryName, queryOPT, queryDO, ok := parseCNAMECompletionQuery(query)
		if !ok {
			t.Fatal("changed response came from an ineligible query")
		}
		var p dns.Parser
		h, err := p.Start(got)
		if err != nil {
			t.Fatal(err)
		}
		if h.ID != queryHeader.ID ||
			!h.Response ||
			h.RCode != dns.RCodeSuccess ||
			h.Authoritative ||
			h.AuthenticData ||
			h.Truncated {
			t.Fatalf("invalid changed header: %+v", h)
		}
		questions, err := p.AllQuestions()
		if err != nil || len(questions) != 1 || questions[0] != queryQuestion {
			t.Fatalf("invalid changed question: %+v, %v", questions, err)
		}
		answers, err := p.AllAnswers()
		if err != nil || len(answers) < 1 {
			t.Fatalf("invalid changed answers: %d, %v", len(answers), err)
		}
		cnameCount := len(answers)
		hasTerminalAddress := answers[len(answers)-1].Header.Type == queryQuestion.Type
		if hasTerminalAddress {
			cnameCount--
		}
		if cnameCount == 0 {
			t.Fatal("changed response has no CNAME")
		}
		current := queryName
		for i, answer := range answers[:cnameCount] {
			if answer.Header.Type != dns.TypeCNAME {
				t.Fatalf("answer %d has type %v, want CNAME", i, answer.Header.Type)
			}
			owner, ok := messageNameToFQDN(answer.Header.Name)
			if !ok || owner != current {
				t.Fatalf("answer %d owner = %q, want %q", i, owner, current)
			}
			cname, ok := answer.Body.(*dns.CNAMEResource)
			if !ok {
				t.Fatalf("answer %d body = %T, want CNAME", i, answer.Body)
			}
			current, ok = messageNameToFQDN(cname.CNAME)
			if !ok {
				t.Fatalf("answer %d has invalid target", i)
			}
		}
		addrs, found := r.lookupLocalHost(current)
		if !found {
			t.Fatalf("changed chain target %q is not locally known", current)
		}
		wantTerminalAddress := false
		for _, ip := range addrs {
			wantTerminalAddress = wantTerminalAddress ||
				(queryQuestion.Type == dns.TypeA && ip.Is4()) ||
				(queryQuestion.Type == dns.TypeAAAA && ip.Is6())
		}
		if hasTerminalAddress != wantTerminalAddress {
			t.Fatalf("terminal address present = %v, want %v", hasTerminalAddress, wantTerminalAddress)
		}
		if hasTerminalAddress {
			terminal := answers[len(answers)-1]
			terminalOwner, ok := messageNameToFQDN(terminal.Header.Name)
			if !ok || terminalOwner != current {
				t.Fatalf("invalid terminal answer: %+v, chain target %q", terminal.Header, current)
			}
			switch queryQuestion.Type {
			case dns.TypeA:
				if _, ok := terminal.Body.(*dns.AResource); !ok {
					t.Fatalf("terminal body = %T, want A", terminal.Body)
				}
			case dns.TypeAAAA:
				if _, ok := terminal.Body.(*dns.AAAAResource); !ok {
					t.Fatalf("terminal body = %T, want AAAA", terminal.Body)
				}
			}
		}
		authorities, err := p.AllAuthorities()
		if err != nil || len(authorities) != 0 {
			t.Fatalf("changed authorities = %d, %v; want none", len(authorities), err)
		}
		additionals, err := p.AllAdditionals()
		if err != nil {
			t.Fatal(err)
		}
		if len(additionals) != 0 && len(additionals) != 1 {
			t.Fatalf("changed additionals = %d, want zero or one", len(additionals))
		}
		if queryOPT != (len(additionals) == 1) {
			t.Fatalf("query OPT = %v, response additionals = %d", queryOPT, len(additionals))
		}
		if queryOPT {
			opt, ok := additionals[0].Body.(*dns.OPTResource)
			if !ok ||
				additionals[0].Header.Class != dns.Class(maxResponseBytes) ||
				additionals[0].Header.DNSSECAllowed() != queryDO ||
				len(opt.Options) != 0 {
				t.Fatalf("invalid changed OPT: %+v", additionals[0])
			}
		}
	})
}

func setCNAMEHeaderZ(msg []byte) []byte {
	out := bytes.Clone(msg)
	out[3] |= dnsHeaderZ
	return out
}

func adjustCNAMETestRDataLength(t testing.TB, msg []byte, typ dns.Type, delta int) []byte {
	t.Helper()
	out := bytes.Clone(msg)
	off := cnameTestRDataLengthOffset(t, out, typ)
	oldLength := int(binary.BigEndian.Uint16(out[off : off+2]))
	newLength := oldLength + delta
	if newLength < 0 || newLength > 1<<16-1 {
		t.Fatalf("adjusted RDLENGTH %d is out of range", newLength)
	}
	binary.BigEndian.PutUint16(out[off:off+2], uint16(newLength))
	if delta > 0 {
		out = append(out, make([]byte, delta)...)
	}
	return out
}

func cnameTestRDataLengthOffset(t testing.TB, msg []byte, wantType dns.Type) int {
	t.Helper()
	if len(msg) < headerBytes {
		t.Fatal("short DNS message")
	}
	off := headerBytes
	for range int(binary.BigEndian.Uint16(msg[4:6])) {
		var ok bool
		off, ok = skipDNSWireName(msg, off, len(msg))
		if !ok || off > len(msg)-4 {
			t.Fatal("invalid question framing")
		}
		off += 4
	}
	for _, countOffset := range [...]int{6, 8, 10} {
		for range int(binary.BigEndian.Uint16(msg[countOffset : countOffset+2])) {
			var ok bool
			off, ok = skipDNSWireName(msg, off, len(msg))
			if !ok || off > len(msg)-dnsResourceFixed {
				t.Fatal("invalid resource framing")
			}
			typ := dns.Type(binary.BigEndian.Uint16(msg[off : off+2]))
			lengthOffset := off + 8
			rdataLen := int(binary.BigEndian.Uint16(msg[lengthOffset : lengthOffset+2]))
			rdataStart := off + dnsResourceFixed
			if rdataLen > len(msg)-rdataStart {
				t.Fatal("invalid resource length")
			}
			if typ == wantType {
				return lengthOffset
			}
			off = rdataStart + rdataLen
		}
	}
	t.Fatalf("DNS message has no %v resource", wantType)
	return 0
}

type cnameTestEdge struct {
	owner  string
	target string
	ttl    uint32
}

type cnameTestOPT struct {
	payload  int
	dnssecOK bool
	extraTTL uint32
	options  []dns.Option
}

type cnameTestMessage struct {
	header         dns.Header
	questions      []dns.Question
	edges          []cnameTestEdge
	answerType     dns.Type
	terminalOwner  string
	terminalIP     netip.Addr
	authorityTypes []dns.Type
	opts           []cnameTestOPT
	additionalType dns.Type
	trailing       []byte
}

func cnameTestQuestion(name string, typ dns.Type) dns.Question {
	return dns.Question{
		Name:  dns.MustNewName(name),
		Type:  typ,
		Class: dns.ClassINET,
	}
}

func makeCNAMETestMessage(t testing.TB, spec cnameTestMessage) []byte {
	t.Helper()
	b := dns.NewBuilder(nil, spec.header)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, question := range spec.questions {
		if err := b.Question(question); err != nil {
			t.Fatal(err)
		}
	}
	if len(spec.edges) != 0 || spec.answerType != 0 || spec.terminalIP.IsValid() {
		if err := b.StartAnswers(); err != nil {
			t.Fatal(err)
		}
		for _, edge := range spec.edges {
			if err := b.CNAMEResource(dns.ResourceHeader{
				Name:  dns.MustNewName(edge.owner),
				Type:  dns.TypeCNAME,
				Class: dns.ClassINET,
				TTL:   edge.ttl,
			}, dns.CNAMEResource{CNAME: dns.MustNewName(edge.target)}); err != nil {
				t.Fatal(err)
			}
		}
		if spec.answerType != 0 {
			if err := b.UnknownResource(dns.ResourceHeader{
				Name:  spec.questions[0].Name,
				Type:  spec.answerType,
				Class: dns.ClassINET,
				TTL:   60,
			}, dns.UnknownResource{Data: []byte{0}}); err != nil {
				t.Fatal(err)
			}
		}
		if spec.terminalIP.IsValid() {
			if err := marshalIP(dns.MustNewName(spec.terminalOwner), spec.terminalIP, &b); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(spec.authorityTypes) != 0 {
		if err := b.StartAuthorities(); err != nil {
			t.Fatal(err)
		}
		for _, typ := range spec.authorityTypes {
			if typ == dns.TypeSOA {
				if err := marshalSOA("ts.net.", &b); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if err := b.UnknownResource(dns.ResourceHeader{
				Name:  dns.MustNewName("ts.net."),
				Type:  typ,
				Class: dns.ClassINET,
				TTL:   60,
			}, dns.UnknownResource{Data: []byte{0}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(spec.opts) != 0 || spec.additionalType != 0 {
		if err := b.StartAdditionals(); err != nil {
			t.Fatal(err)
		}
		for _, opt := range spec.opts {
			var h dns.ResourceHeader
			if err := h.SetEDNS0(opt.payload, dns.RCodeSuccess, opt.dnssecOK); err != nil {
				t.Fatal(err)
			}
			h.TTL |= opt.extraTTL
			if err := b.OPTResource(h, dns.OPTResource{Options: opt.options}); err != nil {
				t.Fatal(err)
			}
		}
		if spec.additionalType != 0 {
			if err := b.UnknownResource(dns.ResourceHeader{
				Name:  dns.MustNewName("extra.example.com."),
				Type:  spec.additionalType,
				Class: dns.ClassINET,
				TTL:   60,
			}, dns.UnknownResource{Data: []byte{0}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return append(out, spec.trailing...)
}
