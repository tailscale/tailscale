// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"encoding/json"
	"testing"

	"tailscale.com/tstest"
)

type doctorOutput struct {
	Checks []doctorCheck `json:"checks"`
}

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

func (o doctorOutput) find(name string) (doctorCheck, bool) {
	for _, c := range o.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return doctorCheck{}, false
}

func runDoctorCmd(t *testing.T, n *TestNode, extraArgs ...string) doctorOutput {
	t.Helper()
	args := append([]string{"doctor", "--json"}, extraArgs...)
	cmd := n.TailscaleForOutput(args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	var result doctorOutput
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("parse doctor JSON: %v\n%s", err, out)
	}
	return result
}

func assertCheck(t *testing.T, out doctorOutput, checkName, wantStatus string) {
	t.Helper()
	c, ok := out.find(checkName)
	if !ok {
		t.Errorf("check %q not found in output", checkName)
		return
	}
	if c.Status != wantStatus {
		t.Errorf("check %q status = %q, want %q (message: %s)", checkName, c.Status, wantStatus, c.Message)
	}
}

// TestDoctorRunning verifies that daemon and auth checks pass when a node is
// fully connected to the tailnet.
func TestDoctorRunning(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()
	defer d1.MustCleanShutdown(t)

	n1.AwaitResponding()
	n1.MustUp()
	n1.AwaitRunning()

	out := runDoctorCmd(t, n1)
	assertCheck(t, out, "Daemon", "pass")
	assertCheck(t, out, "Auth", "pass")
}

// TestDoctorNotLoggedIn verifies that the auth check fails when the daemon is
// running but the node has not logged in.
func TestDoctorNotLoggedIn(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()
	defer d1.MustCleanShutdown(t)

	n1.AwaitResponding()
	// Deliberately no MustUp — daemon is running but not logged in.

	out := runDoctorCmd(t, n1, "--check", "auth")
	assertCheck(t, out, "Auth", "fail")
}

// TestDoctorExpiredKey verifies that the auth check fails after the control
// server expires all node keys.
func TestDoctorExpiredKey(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()
	defer d1.MustCleanShutdown(t)

	n1.AwaitResponding()
	n1.MustUp()
	n1.AwaitRunning()

	env.Control.SetExpireAllNodes(true)
	n1.AwaitNeedsLogin()

	out := runDoctorCmd(t, n1, "--check", "auth")
	assertCheck(t, out, "Auth", "fail")
}

// TestDoctorWithPeers verifies that the acl check passes when two nodes are
// connected to the same tailnet and can reach each other.
func TestDoctorWithPeers(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)
	n2 := NewTestNode(t, env)
	d1 := n1.StartDaemon()
	d2 := n2.StartDaemon()
	defer d1.MustCleanShutdown(t)
	defer d2.MustCleanShutdown(t)

	n1.AwaitResponding()
	n2.AwaitResponding()
	n1.MustUp()
	n2.MustUp()
	n1.AwaitRunning()
	n2.AwaitRunning()

	out := runDoctorCmd(t, n1, "--check", "acl")
	assertCheck(t, out, "ACL", "pass")
}
