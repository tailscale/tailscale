// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"strings"
	"testing"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestUbuntuSystemdUnit runs tailscaled on an Ubuntu node via the stock
// systemd unit that Linux packages ship (cmd/tailscaled/tailscaled.service)
// rather than launching the binary directly, exercising the unit's
// directives (EnvironmentFile, RuntimeDirectory, StateDirectory) and its
// Type=notify readiness handshake. Env.Start already asserts that the node
// reaches the Running backend state under that unit.
func TestUbuntuSystemdUnit(t *testing.T) {
	env := vmtest.New(t)
	node := env.AddNode("node",
		env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT),
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.SystemdUnit())
	env.Start()

	// With Type=notify, systemd only reports the unit active after
	// tailscaled sends READY=1, so this also verifies the sd_notify
	// handshake worked.
	out, err := env.SSHExec(node, "systemctl is-active tailscaled.service")
	if err != nil {
		t.Fatalf("systemctl is-active: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(out); got != "active" {
		t.Fatalf("tailscaled.service state = %q, want %q", got, "active")
	}

	// Verify the tailscaled that TTA talked to is the one systemd runs,
	// not a stray process started some other way.
	out, err = env.SSHExec(node, `test "$(systemctl show -p MainPID --value tailscaled.service)" = "$(pidof tailscaled)" && echo match`)
	if err != nil {
		t.Fatalf("MainPID check: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(out); got != "match" {
		t.Fatalf("MainPID check output = %q, want %q", got, "match")
	}
}
