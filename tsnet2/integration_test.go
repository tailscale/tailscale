// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet2_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet2"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// trafficRecord is the on-disk shape of a single JSON Lines record
// written by the daemon's traffic logger. The schema mirrors the one
// in PLAN.tsnet2.md ("Traffic logging").
type trafficRecord struct {
	T          string         `json:"t"`
	Kind       string         `json:"kind"` // "open" | "data" | "close"
	ConnID     string         `json:"conn_id"`
	Dir        string         `json:"dir,omitempty"`
	ListenerID string         `json:"listener_id,omitempty"`
	Local      string         `json:"local,omitempty"`
	Remote     string         `json:"remote,omitempty"`
	Proto      string         `json:"proto,omitempty"`
	WhoIs      map[string]any `json:"whois,omitempty"`
	Seq        int            `json:"seq,omitempty"`
	Len        int            `json:"len,omitempty"`
	PayloadB64 string         `json:"payload_b64,omitempty"`
	BytesIn    int64          `json:"bytes_in,omitempty"`
	BytesOut   int64          `json:"bytes_out,omitempty"`
	DurationMs int64          `json:"duration_ms,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// TestTsnet2EndToEnd is the RED integration test that defines the bar
// the implementation has to clear. It exercises the full intended
// pipeline:
//
//  1. Build the cmd/tsnet2d binary into the test's temp dir.
//  2. Stand up a fake control plane (testcontrol.Server) plus DERP/STUN
//     the same way tsnet/tsnet_test.go does.
//  3. Launch two tsnet2d daemon subprocesses on separate sockets.
//  4. Stand up two tsnet2.Servers, each pointed at one daemon socket,
//     and call Up.
//  5. Listen on server A, dial from server B, exchange a known payload,
//     verify echo round-trip.
//  6. Use server B's LocalClient to WhoIs server A's IP (validates
//     LocalAPI proxying).
//  7. Read server A's daemon traffic log and assert it contains
//     open / data / close records with the expected schema.
//
// All of this is expected to FAIL today because the package and the
// daemon are skeletons. The first failure is at step 1 (no binary
// builds) or step 4 (Up returns "not implemented"). Either way, the
// failure is structured: t.Fatalf with a message that says which
// expectation was unmet.
func TestTsnet2EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("tsnet2 daemon uses Unix sockets; skipping on windows")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Step 1: build the daemon. Failing here is "tsnet2d does not yet
	// build at all" — which it does in skeleton form, so this should
	// succeed even RED.
	tmp := t.TempDir()
	daemonBin := filepath.Join(tmp, "tsnet2d")
	if runtime.GOOS == "windows" {
		daemonBin += ".exe"
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", daemonBin, "tailscale.com/cmd/tsnet2d")
	build.Stderr = newPrefixWriter(t, "go build tsnet2d: ")
	if err := build.Run(); err != nil {
		t.Fatalf("building cmd/tsnet2d: %v", err)
	}

	// Step 2: control plane + DERP/STUN.
	controlURL, _ := startControl(t)

	// Step 3 & 4: bring up server A and server B against their own daemons.
	srvA, _, daemonALog := startTsnet2(ctx, t, daemonBin, controlURL, "tsnet2-a")
	srvB, _, _ := startTsnet2(ctx, t, daemonBin, controlURL, "tsnet2-b")

	statusA, err := srvA.Up(ctx)
	if err != nil {
		t.Fatalf("srvA.Up: %v (expected: implementation pending; integration test should pass once daemon is real)", err)
	}
	if _, err := srvB.Up(ctx); err != nil {
		t.Fatalf("srvB.Up: %v", err)
	}
	if len(statusA.TailscaleIPs) == 0 {
		t.Fatalf("srvA.Up returned status with no Tailscale IPs")
	}
	aIP := statusA.TailscaleIPs[0]

	// Step 5: TCP echo over the tailnet.
	ln, err := srvA.Listen("tcp", ":8080")
	if err != nil {
		t.Fatalf("srvA.Listen: %v", err)
	}
	defer ln.Close()

	acceptErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptErr <- fmt.Errorf("accept: %w", err)
			return
		}
		defer c.Close()
		// Echo back exactly what we read, once.
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil && err != io.EOF {
			acceptErr <- fmt.Errorf("read: %w", err)
			return
		}
		if _, err := c.Write(buf[:n]); err != nil {
			acceptErr <- fmt.Errorf("write: %w", err)
			return
		}
		acceptErr <- nil
	}()

	dialed, err := srvB.Dial(ctx, "tcp", fmt.Sprintf("%s:8080", aIP))
	if err != nil {
		t.Fatalf("srvB.Dial: %v", err)
	}
	const payload = "hello tsnet2"
	if _, err := io.WriteString(dialed, payload); err != nil {
		t.Fatalf("write to srvA: %v", err)
	}
	gotBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(dialed, gotBuf); err != nil {
		t.Fatalf("read echo from srvA: %v", err)
	}
	if string(gotBuf) != payload {
		t.Fatalf("echo mismatch: got %q, want %q", gotBuf, payload)
	}
	dialed.Close()

	select {
	case err := <-acceptErr:
		if err != nil {
			t.Fatalf("srvA accept goroutine: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for accept goroutine")
	}

	// Step 6: WhoIs round-trip over the proxied LocalAPI.
	lcB, err := srvB.LocalClient()
	if err != nil {
		t.Fatalf("srvB.LocalClient: %v", err)
	}
	who, err := lcB.WhoIs(ctx, fmt.Sprintf("%s:8080", aIP))
	if err != nil {
		t.Fatalf("srvB.LocalClient().WhoIs(%v): %v", aIP, err)
	}
	if who == nil || who.Node == nil {
		t.Fatalf("WhoIs returned no node; expected to find server A's identity")
	}
	if got, want := who.Node.Name, "tsnet2-a"; got != want {
		// Be permissive: tailscale name often has a suffix. We just
		// need the daemon-routed WhoIs to come back populated.
		if !strings.Contains(got, want) {
			t.Fatalf("WhoIs: node name = %q, want it to mention %q", got, want)
		}
	}

	// Step 7: assert the daemon's traffic log captured the conversation.
	records := readTrafficLog(t, daemonALog)
	if len(records) == 0 {
		t.Fatalf("traffic log %s is empty; expected open/data/close records for the echo conn", daemonALog)
	}

	var (
		sawOpen  bool
		sawData  bool
		sawClose bool
	)
	for _, r := range records {
		switch r.Kind {
		case "open":
			// Inbound conn from peer to listener on srvA. Must have
			// WhoIs enrichment per the plan.
			if r.Dir != "in" {
				continue
			}
			if r.WhoIs == nil {
				t.Errorf("open record %s missing whois enrichment", r.ConnID)
			}
			if r.Proto != "tcp" {
				t.Errorf("open record %s proto = %q, want tcp", r.ConnID, r.Proto)
			}
			if r.Local == "" || r.Remote == "" {
				t.Errorf("open record %s missing 5-tuple endpoints (local=%q remote=%q)", r.ConnID, r.Local, r.Remote)
			}
			sawOpen = true
		case "data":
			if r.PayloadB64 == "" {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(r.PayloadB64)
			if err != nil {
				t.Errorf("data record %s: bad base64: %v", r.ConnID, err)
				continue
			}
			if bytes.Contains(decoded, []byte(payload)) {
				sawData = true
			}
		case "close":
			if r.BytesIn == 0 && r.BytesOut == 0 {
				continue
			}
			sawClose = true
		}
	}

	if !sawOpen {
		t.Fatalf("expected an inbound 'open' record with whois in traffic log, got none (records=%d)", len(records))
	}
	if !sawData {
		t.Fatalf("expected a 'data' record whose payload contains %q in traffic log, got none (records=%d)", payload, len(records))
	}
	if !sawClose {
		t.Fatalf("expected a 'close' record with non-zero byte counts in traffic log, got none (records=%d)", len(records))
	}
}

// readTrafficLog returns every JSON Lines record from path. If the file
// does not exist or is empty it returns nil.
func readTrafficLog(t *testing.T, path string) []trafficRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Logf("traffic log %s does not exist", path)
			return nil
		}
		t.Fatalf("open traffic log: %v", err)
	}
	defer f.Close()
	var out []trafficRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<16), 1<<24)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec trafficRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("traffic log %s: bad JSON line %q: %v", path, line, err)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan traffic log: %v", err)
	}
	return out
}

// startTsnet2 launches a tsnet2d subprocess and returns a tsnet2.Server
// pointed at its socket plus the path the daemon should write its
// traffic log to.
func startTsnet2(ctx context.Context, t *testing.T, daemonBin, controlURL, hostname string) (*tsnet2.Server, *exec.Cmd, string) {
	t.Helper()

	stateDir := filepath.Join(t.TempDir(), hostname)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	socket := filepath.Join(stateDir, "tsnet2.sock")
	trafficLog := filepath.Join(stateDir, "traffic.jsonl")

	cmd := exec.CommandContext(ctx,
		daemonBin,
		"--socket", socket,
		"--state-dir", stateDir,
		"--traffic-log", trafficLog,
	)
	// Daemon picks up control URL and authkey from env, matching how
	// tsnet picks up TS_CONTROL_URL / TS_AUTHKEY.
	cmd.Env = append(os.Environ(),
		"TS_CONTROL_URL="+controlURL,
		"TS_LOG_TARGET=", // disable cloud logging
	)
	cmd.Stderr = newPrefixWriter(t, hostname+"d: ")
	cmd.Stdout = newPrefixWriter(t, hostname+"d: ")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tsnet2d: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	srv := &tsnet2.Server{
		Dir:            stateDir,
		Hostname:       hostname,
		ControlURL:     controlURL,
		Ephemeral:      true,
		SocketPath:     socket,
		TrafficLogPath: trafficLog,
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, cmd, trafficLog
}

// startControl is a copy of tsnet/tsnet_test.go's startControl helper,
// minus the t.Helper-only bits and the cert issuer (tsnet2 does not
// need TLS for this integration test).
func startControl(t *testing.T) (controlURL string, control *testcontrol.Server) {
	t.Helper()
	// Corp#4520: don't use netns for tests.
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control = &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           t.Logf,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL = control.HTTPTestServer.URL
	t.Logf("testcontrol listening on %s", controlURL)
	return controlURL, control
}

// prefixWriter prefixes each newline-terminated chunk of bytes written
// to it with a fixed string before logging via t.Logf. Used for daemon
// subprocess stderr so the test output is legible.
type prefixWriter struct {
	prefix string
	t      *testing.T
}

func newPrefixWriter(t *testing.T, prefix string) io.Writer {
	return &prefixWriter{prefix: prefix, t: t}
}

func (w *prefixWriter) Write(p []byte) (int, error) {
	for _, line := range bytes.Split(bytes.TrimRight(p, "\n"), []byte{'\n'}) {
		w.t.Logf("%s%s", w.prefix, line)
	}
	return len(p), nil
}

// Ensure prefixWriter satisfies io.Writer at compile time.
var _ io.Writer = (*prefixWriter)(nil)
