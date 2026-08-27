// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"encoding/binary"
	"net/netip"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/util/dnsname"
)

const (
	ednsDNSSECOK     = uint32(1 << 15)
	dnsHeaderZ       = byte(1 << 6)
	dnsResourceFixed = 10 // type, class, TTL, and RDLENGTH
)

type cnameRecord struct {
	header dns.ResourceHeader
	body   dns.CNAMEResource
	target dnsname.FQDN
}

// maybeCompleteCNAMEResponse appends a host-backed local A or AAAA record to an
// otherwise complete CNAME-only response. If the local name exists but lacks
// the requested family, it changes NXDOMAIN to NOERROR/NODATA. It deliberately
// does no further network resolution. Any message outside the narrow accepted
// shape is returned byte-for-byte unchanged.
func (r *Resolver) maybeCompleteCNAMEResponse(query, upstream []byte) (out []byte, changed bool) {
	if len(query) > maxResponseBytes ||
		len(upstream) > maxResponseBytes ||
		!validCNAMECompletionFraming(query) ||
		!validCNAMECompletionFraming(upstream) {
		return upstream, false
	}

	queryHeader, question, queryName, queryOPT, queryDO, ok := parseCNAMECompletionQuery(query)
	if !ok {
		return upstream, false
	}

	var p dns.Parser
	responseHeader, err := p.Start(upstream)
	if err != nil ||
		!responseHeader.Response ||
		responseHeader.OpCode != 0 ||
		responseHeader.ID != queryHeader.ID ||
		responseHeader.Truncated ||
		(responseHeader.RCode != dns.RCodeSuccess && responseHeader.RCode != dns.RCodeNameError) {
		return upstream, false
	}
	responseQuestions, err := p.AllQuestions()
	if err != nil || len(responseQuestions) != 1 {
		return upstream, false
	}
	responseQuestion := responseQuestions[0]
	responseName, ok := messageNameToFQDN(responseQuestion.Name)
	if !ok ||
		responseName != queryName ||
		responseQuestion.Type != question.Type ||
		responseQuestion.Class != question.Class {
		return upstream, false
	}

	edges := make(map[dnsname.FQDN]cnameRecord)
	for {
		h, err := p.AnswerHeader()
		if err == dns.ErrSectionDone {
			break
		}
		if err != nil || h.Type != dns.TypeCNAME || h.Class != dns.ClassINET {
			return upstream, false
		}
		body, err := p.CNAMEResource()
		if err != nil {
			return upstream, false
		}
		owner, ok := messageNameToFQDN(h.Name)
		if !ok {
			return upstream, false
		}
		target, ok := messageNameToFQDN(body.CNAME)
		if !ok {
			return upstream, false
		}
		if _, duplicate := edges[owner]; duplicate {
			return upstream, false
		}
		edges[owner] = cnameRecord{header: h, body: body, target: target}
	}
	if len(edges) == 0 {
		return upstream, false
	}

	authorityCount := 0
	for {
		h, err := p.AuthorityHeader()
		if err == dns.ErrSectionDone {
			break
		}
		if err != nil ||
			authorityCount != 0 ||
			h.Type != dns.TypeSOA ||
			h.Class != dns.ClassINET {
			return upstream, false
		}
		if _, err := p.SOAResource(); err != nil {
			return upstream, false
		}
		authorityCount++
	}
	if _, _, ok := parseEmptyCompletionOPT(&p, responseHeader.RCode); !ok {
		return upstream, false
	}

	path := make([]cnameRecord, 0, len(edges))
	seen := make(map[dnsname.FQDN]bool, len(edges))
	terminal := queryName
	for {
		record, ok := edges[terminal]
		if !ok {
			break
		}
		if seen[terminal] {
			return upstream, false
		}
		seen[terminal] = true
		path = append(path, record)
		terminal = record.target
	}
	if len(path) != len(edges) {
		return upstream, false
	}
	if terminal == dnsSymbolicFQDN ||
		dnsname.HasSuffix(terminal.WithoutTrailingDot(), ".onion") {
		return upstream, false
	}
	if _, synthetic := r.resolveViaDomain(terminal, question.Type); synthetic {
		return upstream, false
	}

	addrs, found := r.lookupLocalHost(terminal)
	if !found {
		return upstream, false
	}
	var terminalIP netip.Addr
	for _, ip := range addrs {
		if (question.Type == dns.TypeA && ip.Is4()) ||
			(question.Type == dns.TypeAAAA && ip.Is6()) {
			terminalIP = ip
			break
		}
	}

	b := dns.NewBuilder(nil, dns.Header{
		ID:                 queryHeader.ID,
		Response:           true,
		RecursionDesired:   queryHeader.RecursionDesired,
		RecursionAvailable: responseHeader.RecursionAvailable,
		CheckingDisabled:   queryHeader.CheckingDisabled,
		RCode:              dns.RCodeSuccess,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return upstream, false
	}
	if err := b.Question(question); err != nil {
		return upstream, false
	}
	if err := b.StartAnswers(); err != nil {
		return upstream, false
	}
	for _, record := range path {
		if err := b.CNAMEResource(record.header, record.body); err != nil {
			return upstream, false
		}
	}
	if terminalIP.IsValid() {
		if err := marshalIP(path[len(path)-1].body.CNAME, terminalIP, &b); err != nil {
			return upstream, false
		}
	}
	if queryOPT {
		if err := b.StartAdditionals(); err != nil {
			return upstream, false
		}
		var h dns.ResourceHeader
		if err := h.SetEDNS0(maxResponseBytes, dns.RCodeSuccess, queryDO); err != nil {
			return upstream, false
		}
		if err := b.OPTResource(h, dns.OPTResource{}); err != nil {
			return upstream, false
		}
	}
	out, err = b.Finish()
	if err != nil || len(out) > maxResponseBytes {
		return upstream, false
	}
	return out, true
}

// validCNAMECompletionFraming validates the bounds of every declared DNS
// section and the exact RDLENGTH of the typed CNAME and SOA resources parsed by
// maybeCompleteCNAMEResponse. dnsmessage.Parser does not enforce those typed
// resource boundaries itself. It also rejects the reserved DNS header Z bit.
func validCNAMECompletionFraming(msg []byte) bool {
	if len(msg) < headerBytes || msg[3]&dnsHeaderZ != 0 {
		return false
	}

	off := headerBytes
	questions := int(binary.BigEndian.Uint16(msg[4:6]))
	for range questions {
		var ok bool
		off, ok = skipDNSWireName(msg, off, len(msg))
		if !ok || off > len(msg)-4 {
			return false
		}
		off += 4 // QTYPE and QCLASS
	}

	for _, countOffset := range [...]int{6, 8, 10} {
		count := int(binary.BigEndian.Uint16(msg[countOffset : countOffset+2]))
		for range count {
			var ok bool
			off, ok = skipDNSWireName(msg, off, len(msg))
			if !ok || off > len(msg)-dnsResourceFixed {
				return false
			}
			typ := dns.Type(binary.BigEndian.Uint16(msg[off : off+2]))
			rdataLen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
			rdataStart := off + dnsResourceFixed
			if rdataLen > len(msg)-rdataStart {
				return false
			}
			rdataEnd := rdataStart + rdataLen

			switch typ {
			case dns.TypeCNAME:
				nameEnd, ok := skipDNSWireName(msg, rdataStart, rdataEnd)
				if !ok || nameEnd != rdataEnd {
					return false
				}
			case dns.TypeSOA:
				namesEnd, ok := skipDNSWireName(msg, rdataStart, rdataEnd)
				if ok {
					namesEnd, ok = skipDNSWireName(msg, namesEnd, rdataEnd)
				}
				if !ok || rdataEnd-namesEnd != 5*4 {
					return false
				}
			}
			off = rdataEnd
		}
	}
	return off == len(msg)
}

// skipDNSWireName returns the first byte after one encoded DNS name, bounded by
// end. Compression pointers consume two bytes and are semantically validated
// later by dnsmessage.Parser.
func skipDNSWireName(msg []byte, off, end int) (next int, ok bool) {
	if off < 0 || off >= end || end > len(msg) {
		return 0, false
	}
	for {
		if off >= end {
			return 0, false
		}
		labelLen := int(msg[off])
		off++
		if labelLen == 0 {
			return off, true
		}
		if labelLen&0xc0 == 0xc0 {
			if off >= end {
				return 0, false
			}
			return off + 1, true
		}
		if labelLen&0xc0 != 0 || labelLen > end-off {
			return 0, false
		}
		off += labelLen
	}
}

func parseCNAMECompletionQuery(query []byte) (h dns.Header, q dns.Question, name dnsname.FQDN, hasOPT, do, ok bool) {
	var p dns.Parser
	h, err := p.Start(query)
	if err != nil ||
		h.Response ||
		h.OpCode != 0 ||
		h.Authoritative ||
		h.Truncated ||
		h.RecursionAvailable ||
		h.RCode != dns.RCodeSuccess {
		return dns.Header{}, dns.Question{}, "", false, false, false
	}
	questions, err := p.AllQuestions()
	if err != nil || len(questions) != 1 {
		return dns.Header{}, dns.Question{}, "", false, false, false
	}
	q = questions[0]
	if q.Class != dns.ClassINET || (q.Type != dns.TypeA && q.Type != dns.TypeAAAA) {
		return dns.Header{}, dns.Question{}, "", false, false, false
	}
	name, ok = messageNameToFQDN(q.Name)
	if !ok {
		return dns.Header{}, dns.Question{}, "", false, false, false
	}
	if _, err := p.AnswerHeader(); err != dns.ErrSectionDone {
		return dns.Header{}, dns.Question{}, "", false, false, false
	}
	if _, err := p.AuthorityHeader(); err != dns.ErrSectionDone {
		return dns.Header{}, dns.Question{}, "", false, false, false
	}
	hasOPT, do, ok = parseEmptyCompletionOPT(&p, h.RCode)
	return h, q, name, hasOPT, do, ok
}

func parseEmptyCompletionOPT(p *dns.Parser, rcode dns.RCode) (present, do, ok bool) {
	h, err := p.AdditionalHeader()
	if err == dns.ErrSectionDone {
		return false, false, true
	}
	if err != nil ||
		h.Type != dns.TypeOPT ||
		h.Name.String() != "." ||
		h.TTL&^ednsDNSSECOK != 0 ||
		h.ExtendedRCode(rcode) != rcode {
		return false, false, false
	}
	opt, err := p.OPTResource()
	if err != nil || len(opt.Options) != 0 {
		return false, false, false
	}
	if _, err := p.AdditionalHeader(); err != dns.ErrSectionDone {
		return false, false, false
	}
	return true, h.DNSSECAllowed(), true
}

func messageNameToFQDN(name dns.Name) (dnsname.FQDN, bool) {
	if int(name.Length) > len(name.Data) {
		return "", false
	}
	fqdn, err := dnsname.ToFQDN(rawNameToLower(name.Data[:name.Length]))
	return fqdn, err == nil
}
