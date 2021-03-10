// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdns

import (
	"sort"
	"strings"

	"inet.af/netaddr"
)

// Map is all the data Resolver needs to resolve DNS queries within the Tailscale network.
type Map struct {
	// nameToIP is a mapping of Tailscale domain names to their IP addresses.
	// For example, monitoring.tailscale.us -> 100.64.0.1.
	nameToIP map[string]netaddr.IP
	// ipToName is the inverse of nameToIP.
	ipToName map[netaddr.IP]string
	// names are the keys of nameToIP in sorted order.
	names []string
	// rootDomains are the domains whose subdomains should always
	// be resolved locally to prevent leakage of sensitive names.
	rootDomains []string // e.g. "user.provider.beta.tailscale.net."
}

// NewMap returns a new Map with name to address mapping given by nameToIP.
//
// rootDomains are the domains whose subdomains should always be
// resolved locally to prevent leakage of sensitive names. They should
// end in a period ("user-foo.tailscale.net.").
func NewMap(initNameToIP map[string]netaddr.IP, rootDomains []string) *Map {
	// TODO(dmytro): we have to allocate names and ipToName, but nameToIP can be avoided.
	// It is here because control sends us names not in canonical form. Change this.
	names := make([]string, 0, len(initNameToIP))
	nameToIP := make(map[string]netaddr.IP, len(initNameToIP))
	ipToName := make(map[netaddr.IP]string, len(initNameToIP))

	for name, ip := range initNameToIP {
		if len(name) == 0 {
			// Nothing useful can be done with empty names.
			continue
		}
		if name[len(name)-1] != '.' {
			name += "."
		}
		names = append(names, name)
		nameToIP[name] = ip
		ipToName[ip] = name
	}
	sort.Strings(names)

	return &Map{
		nameToIP: nameToIP,
		ipToName: ipToName,
		names:    names,

		rootDomains: rootDomains,
	}
}

func printSingleNameIP(buf *strings.Builder, name string, ip netaddr.IP) {
	buf.WriteString(name)
	buf.WriteByte('\t')
	buf.WriteString(ip.String())
	buf.WriteByte('\n')
}

func (m *Map) Pretty() string {
	buf := new(strings.Builder)
	for _, name := range m.names {
		printSingleNameIP(buf, name, m.nameToIP[name])
	}
	return buf.String()
}

func (m *Map) PrettyDiffFrom(old *Map) string {
	var (
		oldNameToIP map[string]netaddr.IP
		newNameToIP map[string]netaddr.IP
		oldNames    []string
		newNames    []string
	)
	if old != nil {
		oldNameToIP = old.nameToIP
		oldNames = old.names
	}
	if m != nil {
		newNameToIP = m.nameToIP
		newNames = m.names
	}

	buf := new(strings.Builder)
	space := func() bool {
		return buf.Len() < (1 << 10)
	}

	for len(oldNames) > 0 && len(newNames) > 0 {
		var name string

		newName, oldName := newNames[0], oldNames[0]
		switch {
		case oldName < newName:
			name = oldName
			oldNames = oldNames[1:]
		case oldName > newName:
			name = newName
			newNames = newNames[1:]
		case oldNames[0] == newNames[0]:
			name = oldNames[0]
			oldNames = oldNames[1:]
			newNames = newNames[1:]
		}
		if !space() {
			continue
		}

		ipOld, inOld := oldNameToIP[name]
		ipNew, inNew := newNameToIP[name]
		switch {
		case !inOld:
			buf.WriteByte('+')
			printSingleNameIP(buf, name, ipNew)
		case !inNew:
			buf.WriteByte('-')
			printSingleNameIP(buf, name, ipOld)
		case ipOld != ipNew:
			buf.WriteByte('-')
			printSingleNameIP(buf, name, ipOld)
			buf.WriteByte('+')
			printSingleNameIP(buf, name, ipNew)
		}
	}

	for _, name := range oldNames {
		if !space() {
			break
		}
		if _, ok := newNameToIP[name]; !ok {
			buf.WriteByte('-')
			printSingleNameIP(buf, name, oldNameToIP[name])
		}
	}

	for _, name := range newNames {
		if !space() {
			break
		}
		if _, ok := oldNameToIP[name]; !ok {
			buf.WriteByte('+')
			printSingleNameIP(buf, name, newNameToIP[name])
		}
	}
	if !space() {
		buf.WriteString("... [truncated]\n")
	}

	return buf.String()
}
