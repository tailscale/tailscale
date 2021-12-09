// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"inet.af/netaddr"
)

// This file exists to isolate the test infrastructure
// that depends on github.com/miekg/dns
// from the rest, which only depends on dnsmessage.

// resolveToIP returns a handler function which responds
// to queries of type A it receives with an A record containing ipv4,
// to queries of type AAAA with an AAAA record containing ipv6,
// to queries of type NS with an NS record containing name.
func resolveToIP(ipv4, ipv6 netaddr.IP, ns string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		if len(req.Question) != 1 {
			panic("not a single-question request")
		}
		question := req.Question[0]

		var ans dns.RR
		switch question.Qtype {
		case dns.TypeA:
			ans = &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
				},
				A: ipv4.IPAddr().IP,
			}
		case dns.TypeAAAA:
			ans = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
				},
				AAAA: ipv6.IPAddr().IP,
			}
		case dns.TypeNS:
			ans = &dns.NS{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
				},
				Ns: ns,
			}
		}

		m.Answer = append(m.Answer, ans)
		w.WriteMsg(m)
	}
}

// resolveToIPLowercase returns a handler function which canonicalizes responses
// by lowercasing the question and answer names, and responds
// to queries of type A it receives with an A record containing ipv4,
// to queries of type AAAA with an AAAA record containing ipv6,
// to queries of type NS with an NS record containing name.
func resolveToIPLowercase(ipv4, ipv6 netaddr.IP, ns string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		if len(req.Question) != 1 {
			panic("not a single-question request")
		}
		m.Question[0].Name = strings.ToLower(m.Question[0].Name)
		question := req.Question[0]

		var ans dns.RR
		switch question.Qtype {
		case dns.TypeA:
			ans = &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
				},
				A: ipv4.IPAddr().IP,
			}
		case dns.TypeAAAA:
			ans = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
				},
				AAAA: ipv6.IPAddr().IP,
			}
		case dns.TypeNS:
			ans = &dns.NS{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
				},
				Ns: ns,
			}
		}

		m.Answer = append(m.Answer, ans)
		w.WriteMsg(m)
	}
}

// resolveToTXT returns a handler function which responds to queries of type TXT
// it receives with the strings in txts.
func resolveToTXT(txts []string, ednsMaxSize uint16) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		if len(req.Question) != 1 {
			panic("not a single-question request")
		}
		question := req.Question[0]

		if question.Qtype != dns.TypeTXT {
			w.WriteMsg(m)
			return
		}

		ans := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
			},
			Txt: txts,
		}

		m.Answer = append(m.Answer, ans)

		queryInfo := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "query-info.test.",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
			},
		}

		if edns := req.IsEdns0(); edns == nil {
			queryInfo.Txt = []string{"EDNS=false"}
		} else {
			queryInfo.Txt = []string{"EDNS=true", fmt.Sprintf("maxSize=%v", edns.UDPSize())}
		}

		m.Extra = append(m.Extra, queryInfo)

		if ednsMaxSize > 0 {
			m.SetEdns0(ednsMaxSize, false)
		}

		if err := w.WriteMsg(m); err != nil {
			panic(err)
		}
	}
}

var resolveToNXDOMAIN = dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)
	w.WriteMsg(m)
})

// weirdoGoCNAMEHandler returns a DNS handler that satisfies
// Go's weird Resolver.LookupCNAME (read its godoc carefully!).
//
// This doesn't even return a CNAME record, because that's not
// what Go looks for.
func weirdoGoCNAMEHandler(target string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		question := req.Question[0]

		switch question.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   target,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    600,
				},
				Target: target,
			})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   target,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    600,
				},
				AAAA: net.ParseIP("1::2"),
			})
		}
		w.WriteMsg(m)
	}
}

// dnsHandler returns a handler that replies with the answers/options
// provided.
//
// Types supported: netaddr.IP.
func dnsHandler(answers ...interface{}) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) != 1 {
			panic("not a single-question request")
		}
		m.RecursionAvailable = true // to stop net package's errLameReferral on empty replies

		question := req.Question[0]
		for _, a := range answers {
			switch a := a.(type) {
			default:
				panic(fmt.Sprintf("unsupported dnsHandler arg %T", a))
			case netaddr.IP:
				ip := a
				if ip.Is4() {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
						},
						A: ip.IPAddr().IP,
					})
				} else if ip.Is6() {
					m.Answer = append(m.Answer, &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
						},
						AAAA: ip.IPAddr().IP,
					})
				}
			case dns.PTR:
				ptr := a
				ptr.Hdr = dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
				}
				m.Answer = append(m.Answer, &ptr)
			case dns.CNAME:
				c := a
				c.Hdr = dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    600,
				}
				m.Answer = append(m.Answer, &c)
			case dns.TXT:
				txt := a
				txt.Hdr = dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
				}
				m.Answer = append(m.Answer, &txt)
			case dns.SRV:
				srv := a
				srv.Hdr = dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
				}
				m.Answer = append(m.Answer, &srv)
			case dns.NS:
				rr := a
				rr.Hdr = dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
				}
				m.Answer = append(m.Answer, &rr)
			}
		}
		w.WriteMsg(m)
	}
}

func serveDNS(tb testing.TB, addr string, records ...interface{}) *dns.Server {
	if len(records)%2 != 0 {
		panic("must have an even number of record values")
	}
	mux := dns.NewServeMux()
	for i := 0; i < len(records); i += 2 {
		name := records[i].(string)
		handler := records[i+1].(dns.Handler)
		mux.Handle(name, handler)
	}
	waitch := make(chan struct{})
	server := &dns.Server{
		Addr:              addr,
		Net:               "udp",
		Handler:           mux,
		NotifyStartedFunc: func() { close(waitch) },
		ReusePort:         true,
	}

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			panic(fmt.Sprintf("ListenAndServe(%q): %v", addr, err))
		}
	}()

	<-waitch
	return server
}
