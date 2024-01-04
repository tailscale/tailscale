// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

// An OSConfigurator applies DNS settings to the operating system.
type OSConfigurator interface {
	// SetDNS updates the OS's DNS configuration to match cfg.
	// If cfg is the zero value, all Tailscale-related DNS
	// configuration is removed.
	// SetDNS must not be called after Close.
	// SetDNS takes ownership of cfg.
	SetDNS(cfg OSConfig) error
	// SupportsSplitDNS reports whether the configurator is capable of
	// installing a resolver only for specific DNS suffixes. If false,
	// the configurator can only set a global resolver.
	SupportsSplitDNS() bool
	// GetBaseConfig returns the OS's "base" configuration, i.e. the
	// resolver settings the OS would use without Tailscale
	// contributing any configuration.
	// GetBaseConfig must return the tailscale-free base config even
	// after SetDNS has been called to set a Tailscale configuration.
	// Only works when SupportsSplitDNS=false.

	// Implementations that don't support getting the base config must
	// return ErrGetBaseConfigNotSupported.
	GetBaseConfig() (OSConfig, error)
	// Close removes Tailscale-related DNS configuration from the OS.
	Close() error
}

// HostEntry represents a single line in the OS's hosts file.
type HostEntry struct {
	Addr  netip.Addr
	Hosts []string
}

// OSConfig is an OS DNS configuration.
type OSConfig struct {
	// Hosts is a map of DNS FQDNs to their IPs, which should be added to the
	// OS's hosts file. Currently, (2022-08-12) it is only populated for Windows
	// in SplitDNS mode and with Smart Name Resolution turned on.
	Hosts []*HostEntry
	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netip.Addr
	// SearchDomains are the domain suffixes to use when expanding
	// single-label name queries. SearchDomains is additive to
	// whatever non-Tailscale search domains the OS has.
	SearchDomains []dnsname.FQDN
	// MatchDomains are the DNS suffixes for which Nameservers should
	// be used. If empty, Nameservers is installed as the "primary" resolver.
	// A non-empty MatchDomains requests a "split DNS" configuration
	// from the OS, which will only work with OSConfigurators that
	// report SupportsSplitDNS()=true.
	MatchDomains []dnsname.FQDN
}

func (o *OSConfig) WriteToBufioWriter(w *bufio.Writer) {
	if o == nil {
		w.WriteString("<nil>")
		return
	}
	w.WriteString("{")
	if len(o.Hosts) > 0 {
		fmt.Fprintf(w, "Hosts:%v ", o.Hosts)
	}
	if len(o.Nameservers) > 0 {
		fmt.Fprintf(w, "Nameservers:%v ", o.Nameservers)
	}
	if len(o.SearchDomains) > 0 {
		fmt.Fprintf(w, "SearchDomains:%v ", o.SearchDomains)
	}
	if len(o.MatchDomains) > 0 {
		w.WriteString("SearchDomains:[")
		sp := ""
		var numARPA int
		for _, s := range o.MatchDomains {
			if strings.HasSuffix(string(s), ".arpa.") {
				numARPA++
				continue
			}
			w.WriteString(sp)
			w.WriteString(string(s))
			sp = " "
		}
		w.WriteString("]")
		if numARPA > 0 {
			fmt.Fprintf(w, "+%darpa", numARPA)
		}
	}
	w.WriteString("}")
}

func (o OSConfig) IsZero() bool {
	return len(o.Nameservers) == 0 && len(o.SearchDomains) == 0 && len(o.MatchDomains) == 0
}

func (a OSConfig) Equal(b OSConfig) bool {
	if len(a.Nameservers) != len(b.Nameservers) {
		return false
	}
	if len(a.SearchDomains) != len(b.SearchDomains) {
		return false
	}
	if len(a.MatchDomains) != len(b.MatchDomains) {
		return false
	}

	for i := range a.Nameservers {
		if a.Nameservers[i] != b.Nameservers[i] {
			return false
		}
	}
	for i := range a.SearchDomains {
		if a.SearchDomains[i] != b.SearchDomains[i] {
			return false
		}
	}
	for i := range a.MatchDomains {
		if a.MatchDomains[i] != b.MatchDomains[i] {
			return false
		}
	}

	return true
}

// Format implements the fmt.Formatter interface to ensure that Hosts is
// printed correctly (i.e. not as a bunch of pointers).
//
// Fixes https://github.com/tailscale/tailscale/issues/5669
func (a OSConfig) Format(f fmt.State, verb rune) {
	logger.ArgWriter(func(w *bufio.Writer) {
		w.WriteString(`{Nameservers:[`)
		for i, ns := range a.Nameservers {
			if i != 0 {
				w.WriteString(" ")
			}
			fmt.Fprintf(w, "%+v", ns)
		}
		w.WriteString(`] SearchDomains:[`)
		for i, domain := range a.SearchDomains {
			if i != 0 {
				w.WriteString(" ")
			}
			fmt.Fprintf(w, "%+v", domain)
		}
		w.WriteString(`] MatchDomains:[`)
		for i, domain := range a.MatchDomains {
			if i != 0 {
				w.WriteString(" ")
			}
			fmt.Fprintf(w, "%+v", domain)
		}
		w.WriteString(`] Hosts:[`)
		for i, host := range a.Hosts {
			if i != 0 {
				w.WriteString(" ")
			}
			fmt.Fprintf(w, "%+v", host)
		}
		w.WriteString(`]}`)
	}).Format(f, verb)
}

// ErrGetBaseConfigNotSupported is the error
// OSConfigurator.GetBaseConfig returns when the OSConfigurator
// doesn't support reading the underlying configuration out of the OS.
var ErrGetBaseConfigNotSupported = errors.New("getting OS base config is not supported")
