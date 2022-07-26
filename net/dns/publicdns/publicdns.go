// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package publicdns contains mapping and helpers for working with
// public DNS providers.
package publicdns

import (
	"net/netip"
	"sync"

	"tailscale.com/net/netaddr"
)

var knownDoH = map[netaddr.IP]string{} // 8.8.8.8 => "https://..."
var dohIPsOfBase = map[string][]netaddr.IP{}
var populateOnce sync.Once

// KnownDoH returns a map of well-known public DNS IPs to their DoH URL.
// The returned map should not be modified.
func KnownDoH() map[netaddr.IP]string {
	populateOnce.Do(populate)
	return knownDoH
}

// DoHIPsOfBase returns a map of DNS server IP addresses keyed
// by their DoH URL. It is the inverse of KnownDoH.
func DoHIPsOfBase() map[string][]netaddr.IP {
	populateOnce.Do(populate)
	return dohIPsOfBase
}

// DoHV6 returns the first IPv6 DNS address from a given public DNS provider
// if found, along with a boolean indicating success.
func DoHV6(base string) (ip netaddr.IP, ok bool) {
	populateOnce.Do(populate)
	for _, ip := range dohIPsOfBase[base] {
		if ip.Is6() {
			return ip, true
		}
	}
	return ip, false
}

// addDoH parses a given well-formed ip string into a netaddr.IP type and
// adds it to both knownDoH and dohIPsOFBase maps.
func addDoH(ipStr, base string) {
	ip := netip.MustParseAddr(ipStr)
	knownDoH[ip] = base
	dohIPsOfBase[base] = append(dohIPsOfBase[base], ip)
}

// populate is called once to initialize the knownDoH and dohIPsOfBase maps.
func populate() {
	// Cloudflare
	addDoH("1.1.1.1", "https://cloudflare-dns.com/dns-query")
	addDoH("1.0.0.1", "https://cloudflare-dns.com/dns-query")
	addDoH("2606:4700:4700::1111", "https://cloudflare-dns.com/dns-query")
	addDoH("2606:4700:4700::1001", "https://cloudflare-dns.com/dns-query")

	// Cloudflare -Malware
	addDoH("1.1.1.2", "https://security.cloudflare-dns.com/dns-query")
	addDoH("1.0.0.2", "https://security.cloudflare-dns.com/dns-query")
	addDoH("2606:4700:4700::1112", "https://security.cloudflare-dns.com/dns-query")
	addDoH("2606:4700:4700::1002", "https://security.cloudflare-dns.com/dns-query")

	// Cloudflare -Malware -Adult
	addDoH("1.1.1.3", "https://family.cloudflare-dns.com/dns-query")
	addDoH("1.0.0.3", "https://family.cloudflare-dns.com/dns-query")
	addDoH("2606:4700:4700::1113", "https://family.cloudflare-dns.com/dns-query")
	addDoH("2606:4700:4700::1003", "https://family.cloudflare-dns.com/dns-query")

	// Google
	addDoH("8.8.8.8", "https://dns.google/dns-query")
	addDoH("8.8.4.4", "https://dns.google/dns-query")
	addDoH("2001:4860:4860::8888", "https://dns.google/dns-query")
	addDoH("2001:4860:4860::8844", "https://dns.google/dns-query")

	// OpenDNS
	// TODO(bradfitz): OpenDNS is unique amongst this current set in that
	// its DoH DNS names resolve to different IPs than its normal DNS
	// IPs. Support that later. For now we assume that they're the same.
	// addDoH("208.67.222.222", "https://doh.opendns.com/dns-query")
	// addDoH("208.67.220.220", "https://doh.opendns.com/dns-query")
	// addDoH("208.67.222.123", "https://doh.familyshield.opendns.com/dns-query")
	// addDoH("208.67.220.123", "https://doh.familyshield.opendns.com/dns-query")

	// Quad9
	addDoH("9.9.9.9", "https://dns.quad9.net/dns-query")
	addDoH("149.112.112.112", "https://dns.quad9.net/dns-query")
	addDoH("2620:fe::fe", "https://dns.quad9.net/dns-query")
	addDoH("2620:fe::fe:9", "https://dns.quad9.net/dns-query")

	// Quad9 -DNSSEC
	addDoH("9.9.9.10", "https://dns10.quad9.net/dns-query")
	addDoH("149.112.112.10", "https://dns10.quad9.net/dns-query")
	addDoH("2620:fe::10", "https://dns10.quad9.net/dns-query")
	addDoH("2620:fe::fe:10", "https://dns10.quad9.net/dns-query")
}
