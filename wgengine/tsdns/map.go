// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdns

import (
	"fmt"
	"strings"

	"inet.af/netaddr"
)

// Map is all the data Resolver needs to resolve DNS queries within the Tailscale network.
type Map struct {
	// domainToIP is a mapping of Tailscale domains to their IP addresses.
	// For example, monitoring.tailscale.us -> 100.64.0.1.
	domainToIP map[string]netaddr.IP
}

// NewMap returns a new Map with domain to address mapping given by domainToIP.
func NewMap(domainToIP map[string]netaddr.IP) *Map {
	return &Map{domainToIP: domainToIP}
}

func printSingleDomain(buf *strings.Builder, domain string, ip netaddr.IP) {
	// Output width is exactly 80 columns.
	fmt.Fprintf(buf, "%-63s %15s\n", domain, ip)
}

func (m *Map) Pretty() string {
	buf := new(strings.Builder)
	for domain, ip := range m.domainToIP {
		printSingleDomain(buf, domain, ip)
	}
	return buf.String()
}

func (m *Map) PrettyDiffFrom(old *Map) string {
	var oldDomainToIP map[string]netaddr.IP
	if old != nil {
		oldDomainToIP = old.domainToIP
	}

	buf := new(strings.Builder)
	for domain, ip1 := range oldDomainToIP {
		if ip2, ok := m.domainToIP[domain]; !ok {
			buf.WriteByte('-')
			printSingleDomain(buf, domain, ip1)
		} else {
			if ip1 != ip2 {
				buf.WriteByte('-')
				printSingleDomain(buf, domain, ip1)
				buf.WriteByte('+')
				printSingleDomain(buf, domain, ip2)
			}
		}
	}
	for domain, ip2 := range m.domainToIP {
		if _, ok := oldDomainToIP[domain]; !ok {
			buf.WriteByte('+')
			printSingleDomain(buf, domain, ip2)
		}
	}
	return buf.String()
}
