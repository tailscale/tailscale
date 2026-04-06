// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"go4.org/mem"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/mak"
	"tailscale.com/util/syspolicy/policyclient"
)

// NewOSConfigurator creates a new OS configurator.
//
// The health tracker, bus and the knobs may be nil and are ignored on this platform.
func NewOSConfigurator(logf logger.Logf, _ *health.Tracker, _ *eventbus.Bus, _ policyclient.Client, _ *controlknobs.Knobs, ifName string) (OSConfigurator, error) {
	return &darwinConfigurator{
		logf:           logf,
		ifName:         ifName,
		resolverDir:    "/etc/resolver",
		resolvConfPath: "/etc/resolv.conf",
	}, nil
}

// darwinConfigurator is the tailscaled-on-macOS DNS OS configurator that
// maintains the Split DNS nameserver entries pointing MagicDNS DNS suffixes
// to 100.100.100.100 using the macOS /etc/resolver/$SUFFIX files.
type darwinConfigurator struct {
	logf           logger.Logf
	ifName         string
	resolverDir    string // default "/etc/resolver"
	resolvConfPath string // default "/etc/resolv.conf"
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

	if err := os.MkdirAll(c.resolverDir, 0755); err != nil {
		return err
	}

	root, err := os.OpenRoot(c.resolverDir)
	if err != nil {
		return err
	}
	defer root.Close()

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
		if err := root.WriteFile(searchFile, sbuf.Bytes(), 0644); err != nil {
			return err
		}
	}

	for _, d := range cfg.MatchDomains {
		fileBase := string(d.WithoutTrailingDot())
		mak.Set(&keep, fileBase, true)

		if !isValidResolverFileName(fileBase) {
			c.logf("[unexpected] invalid resolver domain %q with slashes or colons", fileBase)
			return fmt.Errorf("invalid resolver domain %q: must not contain slashes or colons", fileBase)
		}

		if err := root.WriteFile(fileBase, buf.Bytes(), 0644); err != nil {
			return err
		}
	}
	return c.removeResolverFiles(func(domain string) bool { return !keep[domain] })
}

func isValidResolverFileName(name string) bool {
	// Verify that the filename doesn't contain any characters that
	// might cause issues when used as a filename; os.Root is a
	// defense against path traversal, but prefer a nice error here
	// if we can. These aren't valid for domain names anyway.
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}

	if strings.Contains(name, ":") {
		return false
	}
	return true
}

// GetBaseConfig returns the current OS DNS configuration, extracting it from /etc/resolv.conf.
// We should really be using the SystemConfiguration framework to get this information, as this
// is not a stable public API, and is provided mostly as a compatibility effort with Unix
// tools. Apple might break this in the future. But honestly, parsing the output of `scutil --dns`
// is *even more* likely to break in the future.
func (c *darwinConfigurator) GetBaseConfig() (OSConfig, error) {
	cfg := OSConfig{}

	resolvConf, err := resolvconffile.ParseFile(c.resolvConfPath)
	if err != nil {
		c.logf("failed to parse %s: %v", c.resolvConfPath, err)
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
		c.logf("no nameservers found in %s, DNS resolution might fail", c.resolvConfPath)
	}

	return cfg, nil
}

const macResolverFileHeader = "# Added by tailscaled\n"

// removeResolverFiles deletes all files in /etc/resolver for which the shouldDelete
// func returns true.
func (c *darwinConfigurator) removeResolverFiles(shouldDelete func(domain string) bool) error {
	root, err := os.OpenRoot(c.resolverDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()

	dents, err := fs.ReadDir(root.FS(), ".")
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
		contents, err := root.ReadFile(name)
		if err != nil {
			if os.IsNotExist(err) { // race?
				continue
			}
			return err
		}
		if !mem.HasPrefix(mem.B(contents), mem.S(macResolverFileHeader)) {
			continue
		}
		if err := root.Remove(name); err != nil {
			return err
		}
	}
	return nil
}
