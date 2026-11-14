// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_iptables

package linuxfw

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/types/logger"
)

// TestNewIPTablesRunnerIP6TablesInitFailure checks that a present but
// non-functional ip6tables disables IPv6 instead of failing runner creation.
// The nft flavor of ip6tables exits 1 from "--version" on kernels without
// nf_tables, which used to make tailscaled exit at startup (#20348).
func TestNewIPTablesRunnerIP6TablesInitFailure(t *testing.T) {
	dir := t.TempDir()
	writeScript := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeScript("iptables", "echo 'iptables v1.8.10 (legacy)'\n")
	writeScript("ip6tables", "echo 'ip6tables/1.8.10 Failed to initialize nft: Protocol not supported' >&2\nexit 1\n")
	t.Setenv("PATH", dir)

	// Make the system IPv6 probe pass so the test reaches the ip6tables
	// constructor regardless of the host's IPv6 configuration.
	tstest.Replace(t, &checkIPv6ForTest, func(logger.Logf) error { return nil })

	var logs strings.Builder
	r, err := newIPTablesRunner(func(format string, args ...any) {
		fmt.Fprintf(&logs, format+"\n", args...)
	})
	if err != nil {
		t.Fatalf("newIPTablesRunner: %v", err)
	}
	if r.HasIPV6() {
		t.Error("HasIPV6() = true; want false when ip6tables fails to initialize")
	}
	if r.HasIPV6Filter() || r.HasIPV6NAT() {
		t.Error("IPv6 filter/NAT reported available; want neither")
	}
	if !strings.Contains(logs.String(), "disabling tunneled IPv6 due to ip6tables init failure") {
		t.Errorf("log missing ip6tables init failure line; got:\n%s", logs.String())
	}
}
