// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/net/dns/dnsmessage"
)

// DNSAnswer describes a single answer from a DNS query response.
type DNSAnswer struct {
	Name  string
	TTL   uint32
	Class string
	Type  string
	Body  string
}

// DNSQueryResult contains the result of a DNS query performed via the
// internal Tailscale DNS resolver.
type DNSQueryResult struct {
	Name         string
	QueryType    string
	Resolvers    []DNSResolverInfo
	ResponseCode string
	Answers      []DNSAnswer
}

var dnsQueryCmd = &ffcli.Command{
	Name:       "query",
	ShortUsage: "tailscale dns query <name> [a|aaaa|cname|mx|ns|opt|ptr|srv|txt] [--json]",
	Exec:       runDNSQuery,
	ShortHelp:  "Perform a DNS query",
	LongHelp: strings.TrimSpace(`
The 'tailscale dns query' subcommand performs a DNS query for the specified name
using the internal DNS forwarder (100.100.100.100).

By default, the DNS query will request an A record. Another DNS record type can
be specified as the second parameter.

The output also provides information about the resolver(s) used to resolve the
query.
`),
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("query")
		fs.BoolVar(&dnsQueryArgs.json, "json", false, "output in JSON format")
		return fs
	})(),
}

// dnsQueryArgs are the arguments for the "dns query" subcommand.
var dnsQueryArgs struct {
	json bool
}

func runDNSQuery(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return flag.ErrHelp
	}
	name := args[0]
	queryType := "A"
	if len(args) >= 2 {
		queryType = args[1]
	}

	rawBytes, resolvers, err := localClient.QueryDNS(ctx, name, queryType)
	if err != nil {
		return fmt.Errorf("failed to query DNS: %w", err)
	}

	data := &DNSQueryResult{
		Name:      name,
		QueryType: queryType,
	}

	for _, r := range resolvers {
		data.Resolvers = append(data.Resolvers, makeDNSResolverInfo(r))
	}

	var p dnsmessage.Parser
	header, err := p.Start(rawBytes)
	if err != nil {
		return fmt.Errorf("failed to parse DNS response: %w", err)
	}
	data.ResponseCode = header.RCode.String()

	p.SkipAllQuestions()

	if header.RCode == dnsmessage.RCodeSuccess {
		answers, err := p.AllAnswers()
		if err != nil {
			return fmt.Errorf("failed to parse DNS answers: %w", err)
		}
		data.Answers = make([]DNSAnswer, 0, len(answers))
		for _, a := range answers {
			data.Answers = append(data.Answers, DNSAnswer{
				Name:  a.Header.Name.String(),
				TTL:   a.Header.TTL,
				Class: a.Header.Class.String(),
				Type:  a.Header.Type.String(),
				Body:  makeAnswerBody(a),
			})
		}
	}

	if dnsQueryArgs.json {
		j, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
		printf("%s\n", j)
		return nil
	}
	printf("%s", formatDNSQueryText(data))
	return nil
}

func formatDNSQueryText(data *DNSQueryResult) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "DNS query for %q (%s) using internal resolver:\n", data.Name, data.QueryType)
	fmt.Fprintf(&sb, "\n")
	if len(data.Resolvers) == 1 {
		fmt.Fprintf(&sb, "Forwarding to resolver: %v\n", formatResolverString(data.Resolvers[0]))
	} else {
		fmt.Fprintf(&sb, "Multiple resolvers available:\n")
		for _, r := range data.Resolvers {
			fmt.Fprintf(&sb, "  - %v\n", formatResolverString(r))
		}
	}
	fmt.Fprintf(&sb, "\n")
	fmt.Fprintf(&sb, "Response code: %v\n", data.ResponseCode)
	fmt.Fprintf(&sb, "\n")

	if data.Answers == nil {
		fmt.Fprintf(&sb, "No answers were returned.\n")
		return sb.String()
	}

	if len(data.Answers) == 0 {
		fmt.Fprintf(&sb, "  (no answers found)\n")
	}

	w := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Name\tTTL\tClass\tType\tBody")
	fmt.Fprintln(w, "----\t---\t-----\t----\t----")
	for _, a := range data.Answers {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", a.Name, a.TTL, a.Class, a.Type, a.Body)
	}
	w.Flush()

	fmt.Fprintf(&sb, "\n")
	return sb.String()
}

// formatResolverString formats a DNSResolverInfo for human-readable text output.
func formatResolverString(r DNSResolverInfo) string {
	if len(r.BootstrapResolution) > 0 {
		return fmt.Sprintf("%s (bootstrap: %v)", r.Addr, r.BootstrapResolution)
	}
	return r.Addr
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
