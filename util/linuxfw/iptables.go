// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_iptables

package linuxfw

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unicode"

	"github.com/coreos/go-iptables/iptables"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

func init() {
	isNotExistError = func(err error) bool {
		var e *iptables.Error
		return errors.As(err, &e) && e.IsNotExist()
	}
}

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
//
// If the iptables binary is not found, it returns an underlying exec.ErrNotFound
// error.
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
			Err:  fmt.Errorf("iptables command run fail: %w", errors.Join(err, ip6err)),
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

// newIPTablesRunner constructs a NetfilterRunner that programs iptables rules.
// If the underlying iptables library fails to initialize, that error is
// returned. The runner probes for IPv6 support once at initialization time and
// if not found, no IPv6 rules will be modified for the lifetime of the runner.
func newIPTablesRunner(logf logger.Logf) (*iptablesRunner, error) {
	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	supportsV6, supportsV6NAT, supportsV6Filter := false, false, false
	v6err := CheckIPv6(logf)
	ip6terr := checkIP6TablesExists()
	var ipt6 *iptables.IPTables
	switch {
	case v6err != nil:
		logf("disabling tunneled IPv6 due to system IPv6 config: %v", v6err)
	case ip6terr != nil:
		logf("disabling tunneled IPv6 due to missing ip6tables: %v", ip6terr)
	default:
		supportsV6 = true
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, err
		}
		supportsV6Filter = checkSupportsV6Filter(ipt6, logf)
		supportsV6NAT = checkSupportsV6NAT(ipt6, logf)
		logf("netfilter running in iptables mode v6 = %v, v6filter = %v, v6nat = %v", supportsV6, supportsV6Filter, supportsV6NAT)
	}
	return &iptablesRunner{
		ipt4:              ipt4,
		ipt6:              ipt6,
		v6Available:       supportsV6,
		v6NATAvailable:    supportsV6NAT,
		v6FilterAvailable: supportsV6Filter}, nil
}

// checkSupportsV6Filter returns whether the system has a "filter" table in the
// IPv6 tables. Some container environments such as GitHub codespaces have
// limited local IPv6 support, and containers containing ip6tables, but do not
// have kernel support for IPv6 filtering.
// We will not set ip6tables rules in these instances.
func checkSupportsV6Filter(ipt *iptables.IPTables, logf logger.Logf) bool {
	if ipt == nil {
		return false
	}
	_, filterListErr := ipt.ListChains("filter")
	if filterListErr == nil {
		return true
	}
	logf("ip6tables filtering is not supported on this host: %v", filterListErr)
	return false
}

// checkSupportsV6NAT returns whether the system has a "nat" table in the
// IPv6 netfilter stack.
//
// The nat table was added after the initial release of ipv6
// netfilter, so some older distros ship a kernel that can't NAT IPv6
// traffic.
// ipt must be initialized for IPv6.
func checkSupportsV6NAT(ipt *iptables.IPTables, logf logger.Logf) bool {
	if ipt == nil || ipt.Proto() != iptables.ProtocolIPv6 {
		return false
	}
	_, natListErr := ipt.ListChains("nat")
	if natListErr == nil {
		return true
	}

	// TODO (irbekrm): the following two checks were added before the check
	// above that verifies that nat chains can be listed. It is a
	// container-friendly check (see
	// https://github.com/tailscale/tailscale/issues/11344), but also should
	// be good enough on its own in other environments. If we never observe
	// it falsely succeed, let's remove the other two checks.

	bs, err := os.ReadFile("/proc/net/ip6_tables_names")
	if err != nil {
		return false
	}
	if bytes.Contains(bs, []byte("nat\n")) {
		logf("[unexpected] listing nat chains failed, but /proc/net/ip6_tables_name reports a nat table existing")
		return true
	}
	if exec.Command("modprobe", "ip6table_nat").Run() == nil {
		logf("[unexpected] listing nat chains failed, but modprobe ip6table_nat succeeded")
		return true
	}
	return false
}

func init() {
	hookIPTablesCleanup.Set(ipTablesCleanUp)
}

// ipTablesCleanUp removes all Tailscale added iptables rules.
// Any errors that occur are logged to the provided logf.
func ipTablesCleanUp(logf logger.Logf) {
	switch distro.Get() {
	case distro.Gokrazy, distro.JetKVM:
		// These use nftables and don't have the "iptables" command.
		// Avoid log spam on cleanup. (#12277)
		return
	}
	err := clearRules(iptables.ProtocolIPv4, logf)
	if err != nil {
		logf("linuxfw: clear iptables: %v", err)
	}

	err = clearRules(iptables.ProtocolIPv6, logf)
	if err != nil {
		logf("linuxfw: clear ip6tables: %v", err)
	}
}

// clearRules clears all the iptables rules created by Tailscale
// for the given protocol. If error occurs, it's logged but not returned.
func clearRules(proto iptables.Protocol, logf logger.Logf) error {
	ipt, err := iptables.NewWithProtocol(proto)
	if err != nil {
		return err
	}

	var errs []error

	if err := delTSHook(ipt, "filter", "INPUT", logf); err != nil {
		errs = append(errs, err)
	}
	if err := delTSHook(ipt, "filter", "FORWARD", logf); err != nil {
		errs = append(errs, err)
	}
	if err := delTSHook(ipt, "nat", "POSTROUTING", logf); err != nil {
		errs = append(errs, err)
	}

	if err := delChain(ipt, "filter", "ts-input"); err != nil {
		errs = append(errs, err)
	}
	if err := delChain(ipt, "filter", "ts-forward"); err != nil {
		errs = append(errs, err)
	}

	if err := delChain(ipt, "nat", "ts-postrouting"); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}
