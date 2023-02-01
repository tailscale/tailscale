// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package publicdns contains mapping and helpers for working with
// public DNS providers.
package publicdns

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// dohOfIP maps from public DNS IPs to their DoH base URL.
//
// This does not include NextDNS which is handled specially.
var dohOfIP = map[netip.Addr]string{} // 8.8.8.8 => "https://..."

var dohIPsOfBase = map[string][]netip.Addr{}
var populateOnce sync.Once

// DoHEndpointFromIP returns the DNS-over-HTTPS base URL for a given IP
// and whether it's DoH-only (not speaking DNS on port 53).
//
// The ok result is whether the IP is a known DNS server.
func DoHEndpointFromIP(ip netip.Addr) (dohBase string, dohOnly bool, ok bool) {
	populateOnce.Do(populate)
	if b, ok := dohOfIP[ip]; ok {
		return b, false, true
	}

	// NextDNS DoH URLs are of the form "https://dns.nextdns.io/c3a884"
	// where the path component is the lower 12 bytes of the IPv6 address
	// in lowercase hex without any zero padding.
	if nextDNSv6RangeA.Contains(ip) || nextDNSv6RangeB.Contains(ip) {
		a := ip.As16()
		var sb strings.Builder
		const base = "https://dns.nextdns.io/"
		sb.Grow(len(base) + 12)
		sb.WriteString(base)
		for _, b := range bytes.TrimLeft(a[4:], "\x00") {
			fmt.Fprintf(&sb, "%02x", b)
		}
		return sb.String(), true, true
	}
	return "", false, false
}

// KnownDoHPrefixes returns the list of DoH base URLs.
//
// It returns a new copy each time, sorted. It's meant for tests.
//
// It does not include providers that have customer-specific DoH URLs like
// NextDNS.
func KnownDoHPrefixes() []string {
	populateOnce.Do(populate)
	ret := make([]string, 0, len(dohIPsOfBase))
	for b := range dohIPsOfBase {
		ret = append(ret, b)
	}
	sort.Strings(ret)
	return ret
}

func isSlashOrQuestionMark(r rune) bool {
	return r == '/' || r == '?'
}

// DoHIPsOfBase returns the IP addresses to use to dial the provided DoH base
// URL.
//
// It is basically the inverse of DoHEndpointFromIP with the exception that for
// NextDNS it returns IPv4 addresses that DoHEndpointFromIP doesn't map back.
func DoHIPsOfBase(dohBase string) []netip.Addr {
	populateOnce.Do(populate)
	if s := dohIPsOfBase[dohBase]; len(s) > 0 {
		return s
	}
	if hexStr, ok := strings.CutPrefix(dohBase, "https://dns.nextdns.io/"); ok {
		// The path is of the form /<profile-hex>[/<hostname>/<model>/<device id>...]
		// or /<profile-hex>?<query params>
		// but only the <profile-hex> is required. Ignore the rest:
		if i := strings.IndexFunc(hexStr, isSlashOrQuestionMark); i != -1 {
			hexStr = hexStr[:i]
		}

		// TODO(bradfitz): using the NextDNS anycast addresses works but is not
		// ideal. Some of their regions have better latency via a non-anycast IP
		// which we could get by first resolving A/AAAA "dns.nextdns.io" over
		// DoH using their anycast address. For now we only use the anycast
		// addresses. The IPv4 IPs we use are just the first one in their ranges.
		// For IPv6 we put the profile ID in the lower bytes, but that seems just
		// conventional for them and not required (it'll already be in the DoH path).
		// (Really we shouldn't use either IPv4 or IPv6 anycast for DoH once we
		// resolve "dns.nextdns.io".)
		if b, err := hex.DecodeString(hexStr); err == nil && len(b) <= 12 && len(b) > 0 {
			return []netip.Addr{
				nextDNSv4One,
				nextDNSv4Two,
				nextDNSv6Gen(nextDNSv6RangeA.Addr(), b),
				nextDNSv6Gen(nextDNSv6RangeB.Addr(), b),
			}
		}
	}
	return nil
}

// DoHV6 returns the first IPv6 DNS address from a given public DNS provider
// if found, along with a boolean indicating success.
func DoHV6(base string) (ip netip.Addr, ok bool) {
	populateOnce.Do(populate)
	for _, ip := range dohIPsOfBase[base] {
		if ip.Is6() {
			return ip, true
		}
	}
	return ip, false
}

// addDoH parses a given well-formed ip string into a netip.Addr type and
// adds it to both knownDoH and dohIPsOFBase maps.
func addDoH(ipStr, base string) {
	ip := netip.MustParseAddr(ipStr)
	dohOfIP[ip] = base
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

	// Mullvad
	addDoH("194.242.2.2", "https://doh.mullvad.net/dns-query")
	addDoH("193.19.108.2", "https://doh.mullvad.net/dns-query")
	addDoH("2a07:e340::2", "https://doh.mullvad.net/dns-query")

	// Mullvad -Ads
	addDoH("194.242.2.3", "https://adblock.doh.mullvad.net/dns-query")
	addDoH("193.19.108.3", "https://adblock.doh.mullvad.net/dns-query")
	addDoH("2a07:e340::3", "https://adblock.doh.mullvad.net/dns-query")
}

var (
	// The NextDNS IPv6 ranges (primary and secondary). The customer ID is
	// encoded in the lower bytes and is used (in hex form) as the DoH query
	// path.
	nextDNSv6RangeA = netip.MustParsePrefix("2a07:a8c0::/33")
	nextDNSv6RangeB = netip.MustParsePrefix("2a07:a8c1::/33")

	// The first two IPs in the /24 v4 ranges can be used for DoH to NextDNS.
	//
	// They're Anycast and usually okay, but NextDNS has some locations that
	// don't do BGP and can get results for querying them over DoH to find the
	// IPv4 address of "dns.mynextdns.io" and find an even better result.
	//
	// Note that the Tailscale DNS client does not do any of the "IP address
	// linking" that NextDNS can do with its IPv4 addresses. These addresses
	// are only used for DoH.
	nextDNSv4RangeA = netip.MustParsePrefix("45.90.28.0/24")
	nextDNSv4RangeB = netip.MustParsePrefix("45.90.30.0/24")
	nextDNSv4One    = nextDNSv4RangeA.Addr()
	nextDNSv4Two    = nextDNSv4RangeB.Addr()
)

// nextDNSv6Gen generates a NextDNS IPv6 address from the upper 8 bytes in the
// provided ip and using id as the lowest 0-8 bytes.
func nextDNSv6Gen(ip netip.Addr, id []byte) netip.Addr {
	if len(id) > 12 {
		return netip.Addr{}
	}
	a := ip.As16()
	copy(a[16-len(id):], id)
	return netip.AddrFrom16(a)
}

// IPIsDoHOnlyServer reports whether ip is a DNS server that should only use
// DNS-over-HTTPS (not regular port 53 DNS).
func IPIsDoHOnlyServer(ip netip.Addr) bool {
	return nextDNSv6RangeA.Contains(ip) || nextDNSv6RangeB.Contains(ip) ||
		nextDNSv4RangeA.Contains(ip) || nextDNSv4RangeB.Contains(ip)
}
