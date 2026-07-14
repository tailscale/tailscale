// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package integration

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"tailscale.com/tsconst/wintun"
)

// serviceName is the Windows service tailscaled installs itself as.
const serviceName = "Tailscale"

// startWindowsServiceDaemon installs and starts tailscaled as a Windows service.
func (n *TestNode) startWindowsServiceDaemon() *Daemon {
	t := n.env.t
	t.Helper()

	// A pre-existing Tailscale service means this isn't a disposable/CI machine;
	// fail rather than uninstall it. Stale state is wiped below, not fatal.
	if serviceExists(t) {
		t.Fatal("existing Tailscale service found; run only on a disposable/CI machine")
	}

	n.cleanupServiceState()
	stageWintun(t, filepath.Dir(n.env.daemon))
	n.writeServiceEnvFile()

	if out, err := exec.CommandContext(t.Context(), n.env.daemon, "install-system-daemon").CombinedOutput(); err != nil {
		t.Fatalf("install-system-daemon: %v\n%s", err, out)
	}
	// Teardown (LIFO): stop, uninstall, then wipe state for the next test.
	t.Cleanup(func() {
		n.stopService()
		n.uninstallService()
		n.cleanupServiceState()
	})

	n.startService()
	n.waitServiceReady(90 * time.Second)
	return &Daemon{svc: n}
}

// startService starts the service and waits for the SCM to report it Running.
func (n *TestNode) startService() {
	t := n.env.t
	t.Helper()
	m := connectSCM(t)
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		t.Fatalf("open service %q: %v", serviceName, err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		t.Fatalf("start service %q: %v", serviceName, err)
	}
	n.waitServiceState(s, svc.Running, 60*time.Second)
}

// stopService requests a stop and waits until the service is Stopped, failing
// the test if it doesn't stop in time.
func (n *TestNode) stopService() {
	t := n.env.t
	t.Helper()
	m := connectSCM(t)
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return // not installed; nothing to stop
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		t.Fatalf("query service %q: %v", serviceName, err)
	}
	if st.State == svc.Stopped {
		return
	}
	if _, err := s.Control(svc.Stop); err != nil {
		t.Fatalf("stop service %q: %v", serviceName, err)
	}
	n.waitServiceState(s, svc.Stopped, 60*time.Second)
}

// uninstallService removes the service via tailscaled's uninstall-system-daemon
// and waits until it's gone; a missing service is fine.
func (n *TestNode) uninstallService() {
	t := n.env.t
	t.Helper()
	if !serviceExists(t) {
		return
	}
	// Not t.Context(): this also runs from t.Cleanup, where it's canceled.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, n.env.daemon, "uninstall-system-daemon").CombinedOutput(); err != nil {
		t.Fatalf("uninstall-system-daemon: %v\n%s", err, out)
	}
	n.waitServiceGone(30 * time.Second)
}

// writeServiceEnvFile writes the harness env to the file tailscaled reads at
// startup, since a service doesn't inherit the test process's environment.
func (n *TestNode) writeServiceEnvFile() {
	t := n.env.t
	t.Helper()
	dir := serviceStateDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	dst := filepath.Join(dir, "tailscaled-env.txt")
	body := strings.Join(n.daemonEnv("windows"), "\n") + "\n"
	if err := os.WriteFile(dst, []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", dst, err)
	}
}

// cleanupServiceState removes the service's global state dir so the next test
// doesn't inherit a prior node's identity; call only after the service stops.
func (n *TestNode) cleanupServiceState() {
	t := n.env.t
	t.Helper()
	dir := serviceStateDir()
	if err := os.RemoveAll(dir); err != nil {
		t.Logf("removing %s: %v", dir, err)
	}
}

// serviceStateDir is the global state dir a Tailscale service uses.
func serviceStateDir() string {
	return filepath.Join(os.Getenv("ProgramData"), "Tailscale")
}

// waitServiceReady polls the LocalAPI until BackendState leaves NoState,
// guarding the post-start race (tailscale/tailscale#8695).
func (n *TestNode) waitServiceReady(timeout time.Duration) {
	t := n.env.t
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		st, err := n.Status()
		if err == nil && st.BackendState != "" && st.BackendState != "NoState" {
			return
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("service LocalAPI not ready within %v (last err: %v)", timeout, last)
}

// waitServiceState polls s until it reaches want, failing the test on timeout.
func (n *TestNode) waitServiceState(s *mgr.Service, want svc.State, timeout time.Duration) {
	t := n.env.t
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			t.Fatalf("query service %q: %v", serviceName, err)
		}
		if st.State == want {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("service %q did not reach state %d within %v", serviceName, want, timeout)
}

// waitServiceGone polls until the service no longer exists.
func (n *TestNode) waitServiceGone(timeout time.Duration) {
	t := n.env.t
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !serviceExists(t) {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("service %q still present after %v", serviceName, timeout)
}

// serviceExists reports whether the Tailscale service is currently installed.
func serviceExists(t testing.TB) bool {
	t.Helper()
	m := connectSCM(t)
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// connectSCM connects to the Windows service manager, failing the test on error.
func connectSCM(t testing.TB) *mgr.Mgr {
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect to service manager: %v", err)
	}
	return m
}

// stageWintun downloads and verifies wintun.dll into dir; tailscaled loads it
// from its executable's dir (cmd/tailscaled.fullyQualifiedWintunPath).
func stageWintun(t testing.TB, dir string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), "GET", wintun.URL, nil)
	if err != nil {
		t.Fatalf("wintun request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("downloading wintun: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("downloading %s: HTTP %s", wintun.URL, res.Status)
	}
	zipBytes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading wintun zip: %v", err)
	}
	if sum := sha256.Sum256(zipBytes); hex.EncodeToString(sum[:]) != wintun.SHA256 {
		t.Fatalf("wintun zip sha256 = %s, want %s", hex.EncodeToString(sum[:]), wintun.SHA256)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("opening wintun zip: %v", err)
	}
	member := wintun.DLLZipPath(runtime.GOARCH)
	f, err := zr.Open(member)
	if err != nil {
		t.Fatalf("wintun zip missing %q: %v", member, err)
	}
	defer f.Close()
	out, err := os.Create(filepath.Join(dir, "wintun.dll"))
	if err != nil {
		t.Fatalf("creating wintun.dll: %v", err)
	}
	if _, err := io.Copy(out, f); err != nil {
		out.Close()
		t.Fatalf("extracting wintun.dll: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("closing wintun.dll: %v", err)
	}
}
