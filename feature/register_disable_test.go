// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package feature_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	// Link all the features that tailscaled links, so that this test
	// binary registers the same set that the daemon does.
	_ "tailscale.com/feature/condregister"

	"tailscale.com/feature"
	"tailscale.com/net/netcheck"
)

// childModeEnv, when set in this test binary's own environment, makes
// it print its feature registration state as JSON and exit, instead of
// running tests. TestDisableFeature runs the test binary as a child
// process with TS_DISABLE_FEATURE set, because features register
// themselves from package init, before any test could run.
const childModeEnv = "TS_TEST_FEATURE_DISABLE_CHILD"

// childReport is the JSON printed by the test binary in child mode.
type childReport struct {
	Registered []string `json:"registered"`

	// CaptivePortalHookSet reports whether
	// netcheck.HookStartCaptivePortalDetection was set. That hook is
	// set from the init of feature/captiveportal/netcheckhook, a
	// sub-package with no feature.Register gate of its own, so it
	// verifies the stack-walking backstop in feature.Hook.Set.
	CaptivePortalHookSet bool `json:"captivePortalHookSet"`
}

func TestMain(m *testing.M) {
	if os.Getenv(childModeEnv) != "" {
		printChildReport()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func printChildReport() {
	var rep childReport
	for name := range feature.Registered() {
		rep.Registered = append(rep.Registered, name)
	}
	slices.Sort(rep.Registered)
	rep.CaptivePortalHookSet = netcheck.HookStartCaptivePortalDetection.IsSet()
	json.NewEncoder(os.Stdout).Encode(rep)
}

// childReportForEnv runs this test binary as a child process with
// TS_DISABLE_FEATURE set to disableEnv (or unset, if empty), and
// returns its report.
func childReportForEnv(t *testing.T, disableEnv string) childReport {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), childModeEnv+"=1", "TS_DISABLE_FEATURE="+disableEnv)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running child test binary: %v", err)
	}
	var rep childReport
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("parsing child report %q: %v", out, err)
	}
	return rep
}

func TestDisableFeature(t *testing.T) {
	// Baseline: with the env var unset, everything this binary links
	// registers itself.
	base := childReportForEnv(t, "")
	if len(base.Registered) == 0 {
		t.Fatal("no features registered in child; this test binary links no features")
	}
	if !base.CaptivePortalHookSet {
		t.Fatal("captive portal netcheck hook not set at baseline")
	}

	// Disabling every registered feature must disable every one of
	// them. A feature that ignores TS_DISABLE_FEATURE shows up here as
	// still registered.
	all := childReportForEnv(t, strings.Join(base.Registered, ","))
	for _, name := range all.Registered {
		t.Errorf("feature %q still registered after being disabled", name)
	}
	if all.CaptivePortalHookSet {
		t.Error("captive portal netcheck hook still set after captiveportal was disabled")
	}

	// Spot checks of individual features, including the accepted
	// spellings: the ts_omit_ build-tag prefix, underscores in place of
	// dashes, surrounding spaces, and mixed case.
	tests := []struct {
		disableEnv string
		feature    string
	}{
		{"ssh", "ssh"},
		{"taildrop", "taildrop"},
		{"acme", "acme"},
		{" TS_OMIT_TAILDROP , tailNETLock ", "tailnetlock"},
	}
	for _, tt := range tests {
		rep := childReportForEnv(t, tt.disableEnv)
		if slices.Contains(rep.Registered, tt.feature) {
			t.Errorf("feature %q still registered with TS_DISABLE_FEATURE=%q", tt.feature, tt.disableEnv)
		}
	}

	// An unknown feature name is ignored, not fatal: everything else
	// still registers.
	unknown := childReportForEnv(t, "not-a-feature")
	if len(unknown.Registered) != len(base.Registered) {
		t.Errorf("TS_DISABLE_FEATURE=not-a-feature registered %d features; want %d (the full baseline set)",
			len(unknown.Registered), len(base.Registered))
	}
}
