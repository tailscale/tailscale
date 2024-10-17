// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dnstype

import (
	"errors"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// StringForType returns the string representation of a dnsmessage.Type.
// For example, StringForType(dnsmessage.TypeA) returns "A".
func StringForDNSMessageType(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeALL:
		return "ALL"
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeHINFO:
		return "HINFO"
	case dnsmessage.TypeMINFO:
		return "MINFO"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeOPT:
		return "OPT"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeSOA:
		return "SOA"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeWKS:
		return "WKS"
	}
	return "UNKNOWN"
}

// DNSMessageTypeForString returns the dnsmessage.Type for the given string.
// For example, DNSMessageTypeForString("A") returns dnsmessage.TypeA.
func DNSMessageTypeForString(s string) (t dnsmessage.Type, err error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	switch s {
	case "AAAA":
		return dnsmessage.TypeAAAA, nil
	case "ALL":
		return dnsmessage.TypeALL, nil
	case "A":
		return dnsmessage.TypeA, nil
	case "CNAME":
		return dnsmessage.TypeCNAME, nil
	case "HINFO":
		return dnsmessage.TypeHINFO, nil
	case "MINFO":
		return dnsmessage.TypeMINFO, nil
	case "MX":
		return dnsmessage.TypeMX, nil
	case "NS":
		return dnsmessage.TypeNS, nil
	case "OPT":
		return dnsmessage.TypeOPT, nil
	case "PTR":
		return dnsmessage.TypePTR, nil
	case "SOA":
		return dnsmessage.TypeSOA, nil
	case "SRV":
		return dnsmessage.TypeSRV, nil
	case "TXT":
		return dnsmessage.TypeTXT, nil
	case "WKS":
		return dnsmessage.TypeWKS, nil
	}
	return 0, errors.New("unknown DNS message type: " + s)
}
