// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO(#8502): add support for more architectures
//go:build linux && (arm64 || amd64)

package linuxfw

import (
	"fmt"
	"os/exec"
	"strings"
	"unicode"

	"tailscale.com/types/logger"
	"tailscale.com/util/multierr"
)

// DebugNetfilter prints debug information about iptables rules to the
// provided log function.
func DebugIptables(logf logger.Logf) error {
	// unused.
	return nil
}

// detectIptables returns the number of iptables rules that are present in the
// system, ignoring the default "ACCEPT" rule present in the standard iptables
// chains.
//
// It only returns an error when there is no iptables binary, or when iptables -S
// fails. In all other cases, it returns the number of non-default rules.
func detectIptables() (int, error) {
	// run "iptables -S" to get the list of rules using iptables
	// exec.Command returns an error if the binary is not found
	cmd := exec.Command("iptables", "-S")
	output, err := cmd.Output()
	ip6cmd := exec.Command("ip6tables", "-S")
	ip6output, ip6err := ip6cmd.Output()
	var allLines []string
	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	ip6outputStr := string(ip6output)
	ip6lines := strings.Split(ip6outputStr, "\n")
	switch {
	case err == nil && ip6err == nil:
		allLines = append(lines, ip6lines...)
	case err == nil && ip6err != nil:
		allLines = lines
	case err != nil && ip6err == nil:
		allLines = ip6lines
	default:
		return 0, FWModeNotSupportedError{
			Mode: FirewallModeIPTables,
			Err:  fmt.Errorf("iptables command run fail: %w", multierr.New(err, ip6err)),
		}
	}

	// count the number of non-default rules
	count := 0
	for _, line := range allLines {
		trimmedLine := strings.TrimLeftFunc(line, unicode.IsSpace)
		if line != "" && strings.HasPrefix(trimmedLine, "-A") {
			// if the line is not empty and starts with "-A", it is a rule appended not default
			count++
		}
	}

	// return the count of non-default rules
	return count, nil
}
