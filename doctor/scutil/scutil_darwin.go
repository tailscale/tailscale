// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package scutil

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"tailscale.com/types/logger"
)

func (Check) Run(ctx context.Context, logf logger.Logf) error {
	cmd := exec.CommandContext(ctx, "scutil", "--dns")
	out, err := cmd.CombinedOutput()
	if err != nil {
		logf("error running scutil --dns: %v", err)
		return nil
	}

	parsed, err := parseScutilDNS(logf, string(out))
	if err != nil {
		logf("error parsing scutil --dns output: %v", err)
		return nil
	}

	for _, section := range parsed.Sections {
		logf("section: %s", section.Name)
		for _, entry := range section.Entries {
			logf("  entry: %s", entry.Name)
			for key, val := range entry.Config {
				logf("    %s=%q", key, val)
			}
			for key, list := range entry.ListConfig {
				for i, val := range list {
					logf("    %s[%d]=%q", key, i, val)
				}
			}
		}
	}
	return nil
}

type dnsInfo struct {
	Sections []*dnsSection
}

type dnsSection struct {
	Name    string
	Entries []*dnsEntry
}

type dnsEntry struct {
	Name       string
	Config     map[string]string
	ListConfig map[string][]string
}

var (
	reSpacePrefix = regexp.MustCompile(`\A\s+[^\s]`)
	reNumSuffix   = regexp.MustCompile(`\A(.+)\[(\d+)\]\z`)
)

func parseScutilDNS(logf logger.Logf, data string) (*dnsInfo, error) {
	lines := strings.Split(strings.TrimSpace(data), "\n")
	ret := &dnsInfo{}

	const (
		stateEntry = iota
		stateEntryData
	)
	var (
		currState   int = stateEntry
		currSection *dnsSection
		currEntry   *dnsEntry
	)
	for _, ll := range lines {
		switch currState {
		case stateEntry:
			// We're looking for a new 'resolver' section; if the
			// current line has the 'resolver ' prefix, then we've
			// found one.
			if strings.HasPrefix(ll, "resolver ") {
				currEntry = &dnsEntry{
					Name:       ll,
					Config:     make(map[string]string),
					ListConfig: make(map[string][]string),
				}
				currSection.Entries = append(currSection.Entries, currEntry)
				currState = stateEntryData
				continue
			}

			// Otherwise, if we have a non-blank line treat it as a
			// new section.
			llTrim := strings.TrimSpace(ll)
			if llTrim != "" {
				currSection = &dnsSection{
					Name: llTrim,
				}
				ret.Sections = append(ret.Sections, currSection)

				// Still looking for a new resolver; no state change.
			}

		case stateEntryData:
			// We're inside a 'resolver' section; if the current
			// line doesn't have a prefix of 1 or more spaces, then
			// we're done the current section.
			if !reSpacePrefix.MatchString(ll) {
				// Looking for a new 'resolver' entry.
				currState = stateEntry
				continue
			}

			key, val, ok := strings.Cut(ll, ":")
			if !ok {
				logf("unexpected: did not find ':' in: %q", ll)
				continue
			}

			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)

			// If there's a '[##]' suffix of key, then we treat
			// this as a list of items.
			if sm := reNumSuffix.FindStringSubmatch(key); sm != nil {
				index, err := strconv.Atoi(sm[2])
				if err != nil {
					logf("unexpected: bad index: %q", sm[2])
					continue
				}
				key = sm[1]

				sl := currEntry.ListConfig[key]
				if index == len(sl) {
					sl = append(sl, val)
				} else {
					logf("unexpected: out-of-order index: %d (existing len=%d)", index, len(sl))
					continue
				}
				currEntry.ListConfig[key] = sl
			} else {
				if _, ok := currEntry.Config[key]; ok {
					logf("unexpected: duplicate key %q", key)
					continue
				}
				currEntry.Config[key] = val
			}
		}
	}
	return ret, nil
}
