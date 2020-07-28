// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdns

import (
	"fmt"
	"sort"
	"strings"

	"inet.af/netaddr"
)

// Map is all the data Resolver needs to resolve DNS queries within the Tailscale network.
type Map struct {
	// nameToIP is a mapping of Tailscale domain names to their IP addresses.
	// For example, monitoring.tailscale.us -> 100.64.0.1.
	nameToIP map[string]netaddr.IP
	// names are the keys of nameToIP in sorted order.
	names []string
}

// NewMap returns a new Map with name to address mapping given by nameToIP.
func NewMap(nameToIP map[string]netaddr.IP) *Map {
	names := make([]string, 0, len(nameToIP))
	for name := range nameToIP {
		names = append(names, name)
	}
	sort.Strings(names)

	return &Map{
		nameToIP: nameToIP,
		names:    names,
	}
}

func printSingleNameIP(buf *strings.Builder, name string, ip netaddr.IP) {
	// Output width is exactly 80 columns.
	fmt.Fprintf(buf, "%-63s %15s\n", name, ip)
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
		if _, ok := newNameToIP[name]; !ok {
			buf.WriteByte('-')
			printSingleNameIP(buf, name, oldNameToIP[name])
		}
	}

	for _, name := range newNames {
		if _, ok := oldNameToIP[name]; !ok {
			buf.WriteByte('+')
			printSingleNameIP(buf, name, newNameToIP[name])
		}
	}

	return buf.String()
}
