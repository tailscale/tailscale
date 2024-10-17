// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"os"

	"go4.org/mem"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

// NewOSConfigurator creates a new OS configurator.
//
// The health tracker and the knobs may be nil and are ignored on this platform.
func NewOSConfigurator(logf logger.Logf, _ *health.Tracker, _ *controlknobs.Knobs, ifName string) (OSConfigurator, error) {
	return &darwinConfigurator{logf: logf, ifName: ifName}, nil
}

// darwinConfigurator is the tailscaled-on-macOS DNS OS configurator that
// maintains the Split DNS nameserver entries pointing MagicDNS DNS suffixes
// to 100.100.100.100 using the macOS /etc/resolver/$SUFFIX files.
type darwinConfigurator struct {
	logf   logger.Logf
	ifName string
}

func (c *darwinConfigurator) Close() error {
	c.removeResolverFiles(func(domain string) bool { return true })
	return nil
}

func (c *darwinConfigurator) SupportsSplitDNS() bool {
	return true
}

func (c *darwinConfigurator) SetDNS(cfg OSConfig) error {
	var buf bytes.Buffer
	buf.WriteString(macResolverFileHeader)
	for _, ip := range cfg.Nameservers {
		buf.WriteString("nameserver ")
		buf.WriteString(ip.String())
		buf.WriteString("\n")
	}

	if err := os.MkdirAll("/etc/resolver", 0755); err != nil {
		return err
	}

	var keep map[string]bool

	// Add a dummy file to /etc/resolver with a "search ..." directive if we have
	// search suffixes to add.
	if len(cfg.SearchDomains) > 0 {
		const searchFile = "search.tailscale" // fake DNS suffix+TLD to put our search
		mak.Set(&keep, searchFile, true)
		var sbuf bytes.Buffer
		sbuf.WriteString(macResolverFileHeader)
		sbuf.WriteString("search")
		for _, d := range cfg.SearchDomains {
			sbuf.WriteString(" ")
			sbuf.WriteString(string(d.WithoutTrailingDot()))
		}
		sbuf.WriteString("\n")
		if err := os.WriteFile("/etc/resolver/"+searchFile, sbuf.Bytes(), 0644); err != nil {
			return err
		}
	}

	for _, d := range cfg.MatchDomains {
		fileBase := string(d.WithoutTrailingDot())
		mak.Set(&keep, fileBase, true)
		fullPath := "/etc/resolver/" + fileBase

		if err := os.WriteFile(fullPath, buf.Bytes(), 0644); err != nil {
			return err
		}
	}
	return c.removeResolverFiles(func(domain string) bool { return !keep[domain] })
}

// GetBaseConfig returns the current OS DNS configuration, extracting it from /etc/resolv.conf.
// We should really be using the SystemConfiguration framework to get this information, as this
// is not a stable public API, and is provided mostly as a compatibility effort with Unix
// tools. Apple might break this in the future. But honestly, parsing the output of `scutil --dns`
// is *even more* likely to break in the future.
func (c *darwinConfigurator) GetBaseConfig() (OSConfig, error) {
	cfg := OSConfig{}

	resolvConf, err := resolvconffile.ParseFile("/etc/resolv.conf")
	if err != nil {
		c.logf("failed to parse /etc/resolv.conf: %v", err)
		return cfg, ErrGetBaseConfigNotSupported
	}

	for _, ns := range resolvConf.Nameservers {
		if ns == tsaddr.TailscaleServiceIP() || ns == tsaddr.TailscaleServiceIPv6() {
			// If we find Quad100 in /etc/resolv.conf, we should ignore it
			c.logf("ignoring 100.100.100.100 resolver IP found in /etc/resolv.conf")
			continue
		}
		cfg.Nameservers = append(cfg.Nameservers, ns)
	}
	cfg.SearchDomains = resolvConf.SearchDomains

	if len(cfg.Nameservers) == 0 {
		// Log a warning in case we couldn't find any nameservers in /etc/resolv.conf.
		c.logf("no nameservers found in /etc/resolv.conf, DNS resolution might fail")
	}

	return cfg, nil
}

const macResolverFileHeader = "# Added by tailscaled\n"

// removeResolverFiles deletes all files in /etc/resolver for which the shouldDelete
// func returns true.
func (c *darwinConfigurator) removeResolverFiles(shouldDelete func(domain string) bool) error {
	dents, err := os.ReadDir("/etc/resolver")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, de := range dents {
		if !de.Type().IsRegular() {
			continue
		}
		name := de.Name()
		if !shouldDelete(name) {
			continue
		}
		fullPath := "/etc/resolver/" + name
		contents, err := os.ReadFile(fullPath)
		if err != nil {
			if os.IsNotExist(err) { // race?
				continue
			}
			return err
		}
		if !mem.HasPrefix(mem.B(contents), mem.S(macResolverFileHeader)) {
			continue
		}
		if err := os.Remove(fullPath); err != nil {
			return err
		}
	}
	return nil
}
