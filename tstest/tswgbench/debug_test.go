// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tswgbench

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/tswgbench/netbench"
)

// getText fetches path from v's agent as text.
func (v *vm) getText(path string) string {
	res, err := v.client.Get(v.url(path))
	if err != nil {
		return err.Error()
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return fmt.Sprintf("%s: %s", res.Status, bytes.TrimSpace(b))
	}
	return string(b)
}

// snmpLines returns the lines of /proc/net/snmp (or snmp6) for proto.
func snmpLines(s, proto string) string {
	var out []string
	for line := range strings.SplitSeq(s, "\n") {
		if strings.HasPrefix(line, proto) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// TestLeanDebug runs a short TCP load over the data plane in
// TSWG_LEAN_DEBUG and dumps both VMs' UDP and TCP counters, interface
// statistics, kernel log, and tunnel device state, for debugging, plus the
// /proc or /sys files in TSWG_DEBUG_FILES (space-separated).
func TestLeanDebug(t *testing.T) {
	mode := os.Getenv("TSWG_LEAN_DEBUG")
	if mode == "" {
		t.Skip("set TSWG_LEAN_DEBUG=mode (and TSWG_LEAN=1) to run")
	}
	l := newLab(t, 4)
	addr := netip.AddrPortFrom(l.setup(mode, false), benchPort)
	sender, receiver := benchNode{l.vms[0]}, benchNode{l.vms[1]}
	if err := receiver.Do("POST", fmt.Sprintf("serve?port=%d", benchPort), nil); err != nil {
		t.Fatal(err)
	}
	r, err := netbench.RunTCP(sender, receiver, addr, 1, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: %.0f Mbps", mode, r.Mbps)
	for i, v := range l.vms {
		snmp := v.getText("/file?" + url.Values{"path": {"/proc/net/snmp"}}.Encode())
		t.Logf("VM %d:\n%s\n%s\n%s\n--- /proc/net/dev:\n%s\n--- dmesg (tail):\n%s\n--- show:\n%s",
			i,
			snmpLines(snmp, "Ip:"), snmpLines(snmp, "Udp:"), snmpLines(snmp, "Tcp:"),
			v.getText("/file?"+url.Values{"path": {"/proc/net/dev"}}.Encode()),
			tail(v.getText("/dmesg"), 120),
			v.getText("/show"))
		for f := range strings.FieldsSeq(os.Getenv("TSWG_DEBUG_FILES")) {
			t.Logf("VM %d: %s:\n%s", i, f, v.getText("/file?"+url.Values{"path": {f}}.Encode()))
		}
	}
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
