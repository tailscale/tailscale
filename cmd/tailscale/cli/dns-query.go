// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"text/tabwriter"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
)

func runDNSQuery(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return flag.ErrHelp
	}
	name := args[0]
	queryType := "A"
	if len(args) >= 2 {
		queryType = args[1]
	}
	fmt.Printf("DNS query for %q (%s) using internal resolver:\n", name, queryType)
	fmt.Println()
	bytes, resolvers, err := localClient.QueryDNS(ctx, name, queryType)
	if err != nil {
		fmt.Printf("failed to query DNS: %v\n", err)
		return nil
	}

	if len(resolvers) == 1 {
		fmt.Printf("Forwarding to resolver: %v\n", makeResolverString(*resolvers[0]))
	} else {
		fmt.Println("Multiple resolvers available:")
		for _, r := range resolvers {
			fmt.Printf("  - %v\n", makeResolverString(*r))
		}
	}
	fmt.Println()
	var p dnsmessage.Parser
	header, err := p.Start(bytes)
	if err != nil {
		fmt.Printf("failed to parse DNS response: %v\n", err)
		return err
	}
	fmt.Printf("Response code: %v\n", header.RCode.String())
	fmt.Println()
	p.SkipAllQuestions()
	if header.RCode != dnsmessage.RCodeSuccess {
		fmt.Println("No answers were returned.")
		return nil
	}
	answers, err := p.AllAnswers()
	if err != nil {
		fmt.Printf("failed to parse DNS answers: %v\n", err)
		return err
	}
	if len(answers) == 0 {
		fmt.Println("  (no answers found)")
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Name\tTTL\tClass\tType\tBody")
	fmt.Fprintln(w, "----\t---\t-----\t----\t----")
	for _, a := range answers {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", a.Header.Name.String(), a.Header.TTL, a.Header.Class.String(), a.Header.Type.String(), makeAnswerBody(a))
	}
	w.Flush()

	fmt.Println()
	return nil
}

// makeAnswerBody returns a string with the DNS answer body in a human-readable format.
func makeAnswerBody(a dnsmessage.Resource) string {
	switch a.Header.Type {
	case dnsmessage.TypeA:
		return makeABody(a.Body)
	case dnsmessage.TypeAAAA:
		return makeAAAABody(a.Body)
	case dnsmessage.TypeCNAME:
		return makeCNAMEBody(a.Body)
	case dnsmessage.TypeMX:
		return makeMXBody(a.Body)
	case dnsmessage.TypeNS:
		return makeNSBody(a.Body)
	case dnsmessage.TypeOPT:
		return makeOPTBody(a.Body)
	case dnsmessage.TypePTR:
		return makePTRBody(a.Body)
	case dnsmessage.TypeSRV:
		return makeSRVBody(a.Body)
	case dnsmessage.TypeTXT:
		return makeTXTBody(a.Body)
	default:
		return a.Body.GoString()
	}
}

func makeABody(a dnsmessage.ResourceBody) string {
	if a, ok := a.(*dnsmessage.AResource); ok {
		return netip.AddrFrom4(a.A).String()
	}
	return ""
}
func makeAAAABody(aaaa dnsmessage.ResourceBody) string {
	if a, ok := aaaa.(*dnsmessage.AAAAResource); ok {
		return netip.AddrFrom16(a.AAAA).String()
	}
	return ""
}
func makeCNAMEBody(cname dnsmessage.ResourceBody) string {
	if c, ok := cname.(*dnsmessage.CNAMEResource); ok {
		return c.CNAME.String()
	}
	return ""
}
func makeMXBody(mx dnsmessage.ResourceBody) string {
	if m, ok := mx.(*dnsmessage.MXResource); ok {
		return fmt.Sprintf("%s (Priority=%d)", m.MX, m.Pref)
	}
	return ""
}
func makeNSBody(ns dnsmessage.ResourceBody) string {
	if n, ok := ns.(*dnsmessage.NSResource); ok {
		return n.NS.String()
	}
	return ""
}
func makeOPTBody(opt dnsmessage.ResourceBody) string {
	if o, ok := opt.(*dnsmessage.OPTResource); ok {
		return o.GoString()
	}
	return ""
}
func makePTRBody(ptr dnsmessage.ResourceBody) string {
	if p, ok := ptr.(*dnsmessage.PTRResource); ok {
		return p.PTR.String()
	}
	return ""
}
func makeSRVBody(srv dnsmessage.ResourceBody) string {
	if s, ok := srv.(*dnsmessage.SRVResource); ok {
		return fmt.Sprintf("Target=%s, Port=%d, Priority=%d, Weight=%d", s.Target.String(), s.Port, s.Priority, s.Weight)
	}
	return ""
}
func makeTXTBody(txt dnsmessage.ResourceBody) string {
	if t, ok := txt.(*dnsmessage.TXTResource); ok {
		return fmt.Sprintf("%q", t.TXT)
	}
	return ""
}
func makeResolverString(r dnstype.Resolver) string {
	if len(r.BootstrapResolution) > 0 {
		return fmt.Sprintf("%s (bootstrap: %v)", r.Addr, r.BootstrapResolution)
	}
	return fmt.Sprintf("%s", r.Addr)
}
