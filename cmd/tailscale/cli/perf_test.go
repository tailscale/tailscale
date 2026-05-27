// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tailperf"
)

func TestTailperfHistoryFlagsRegistered(t *testing.T) {
	for _, name := range []string{"log-file", "history", "history-limit", "baseline", "export-support"} {
		if perfCmd.FlagSet.Lookup(name) == nil {
			t.Fatalf("tailscale perf missing --%s flag", name)
		}
	}
}

func TestTailperfPortFlagTracksExplicitSet(t *testing.T) {
	var port uint
	var explicit bool
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	port = uint(tailperf.DefaultPort)
	fs.Var(tailperfPortFlag{dst: &port, explicit: &explicit}, "port", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if explicit {
		t.Fatal("port reported explicit when unset")
	}

	port = uint(tailperf.DefaultPort)
	explicit = false
	fs = flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Var(tailperfPortFlag{dst: &port, explicit: &explicit}, "port", "")
	if err := fs.Parse([]string{"--port=22345"}); err != nil {
		t.Fatal(err)
	}
	if !explicit {
		t.Fatal("port not reported explicit when set")
	}
	if port != 22345 {
		t.Fatalf("port = %d, want 22345", port)
	}
}

func TestParseTailperfListArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		flagAll    bool
		wantList   bool
		wantAll    bool
		wantErrSub string
	}{
		{
			name:     "not list",
			args:     []string{"node-a"},
			wantList: false,
		},
		{
			name:     "list",
			args:     []string{"list"},
			wantList: true,
		},
		{
			name:     "list all after subcommand",
			args:     []string{"list", "--all"},
			wantList: true,
			wantAll:  true,
		},
		{
			name:     "list all from flag parser",
			args:     []string{"list"},
			flagAll:  true,
			wantList: true,
			wantAll:  true,
		},
		{
			name:       "unknown list arg",
			args:       []string{"list", "node-a"},
			wantList:   true,
			wantErrSub: "usage: tailscale perf list",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotList, gotAll, _, err := parseTailperfListArgs(tt.args, tt.flagAll)
			if tt.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if gotList != tt.wantList || gotAll != tt.wantAll {
				t.Fatalf("parseTailperfListArgs = list %v all %v, want list %v all %v", gotList, gotAll, tt.wantList, tt.wantAll)
			}
		})
	}
}

func TestWriteTailperfListReportCommands(t *testing.T) {
	peers := []tailperfListPeer{
		{
			Name:  "busy-mac",
			IP:    "100.64.0.1",
			OS:    "macOS",
			State: "active",
			Path:  "direct",
			Status: &tailperfRemoteStatus{
				Busy: true,
				Rules: []tailcfg.TailperfCapRule{{
					TUNListenPort:       22345,
					UserspaceListenPort: 12345,
				}},
			},
		},
		{
			Name:  "linux-target",
			IP:    "100.64.0.2",
			OS:    "linux",
			State: "online",
			Path:  "derp sfo",
			Status: &tailperfRemoteStatus{
				Rules: []tailcfg.TailperfCapRule{{
					TUNListenPort:       22346,
					UserspaceListenPort: 12346,
				}},
			},
		},
	}

	var b bytes.Buffer
	if err := writeTailperfListReport(&b, peers, tailperfListOptions{
		All:           true,
		Limit:         20,
		CommandPrefix: []string{"tailscale"},
	}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Active Tailperf listeners",
		"busy-mac",
		"tailscale perf -c 100.64.0.1 --no-magic --port=22345",
		"tailscale perf -c 100.64.0.1 --no-tun --no-magic --port=12345",
		"Magic Perf candidates",
		"linux-target",
		"tailscale perf -c 100.64.0.2 --port=22346",
		"tailscale perf -c 100.64.0.2 --no-tun --port=12346",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteTailperfListReportTruncates(t *testing.T) {
	var peers []tailperfListPeer
	for i := range 3 {
		peers = append(peers, tailperfListPeer{
			Name:  fmt.Sprintf("node-%d", i),
			IP:    fmt.Sprintf("100.64.0.%d", i+1),
			State: "online",
			Status: &tailperfRemoteStatus{
				Rules: []tailcfg.TailperfCapRule{{TUNListenPort: uint16(22000 + i)}},
			},
		})
	}

	var b bytes.Buffer
	if err := writeTailperfListReport(&b, peers, tailperfListOptions{
		Limit:         2,
		CommandPrefix: []string{"tailscale"},
	}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "showing 2 of 3 peers; use 'tailscale perf list --all'") {
		t.Fatalf("list output missing truncation notice:\n%s", out)
	}
	if strings.Contains(out, "node-2") {
		t.Fatalf("list output included truncated peer:\n%s", out)
	}

	b.Reset()
	if err := writeTailperfListReport(&b, peers, tailperfListOptions{
		All:           true,
		Limit:         2,
		CommandPrefix: []string{"tailscale"},
	}); err != nil {
		t.Fatal(err)
	}
	out = b.String()
	if !strings.Contains(out, "node-2") {
		t.Fatalf("--all output omitted final peer:\n%s", out)
	}
	if strings.Contains(out, "showing 2 of 3") {
		t.Fatalf("--all output still had truncation notice:\n%s", out)
	}
}

func TestRemoteTailperfStartRequestPortSelection(t *testing.T) {
	cfg := tailperf.ClientConfig{
		Port:     tailperf.DefaultPort,
		Protocol: tailperf.ProtoTCP,
		Duration: 5 * time.Second,
		TUNMode:  tailperf.TUNModeDefault,
	}
	if got := remoteTailperfStartRequest(cfg, false).Port; got != 0 {
		t.Fatalf("implicit port request = %d, want 0", got)
	}

	cfg.Port = 22345
	if got := remoteTailperfStartRequest(cfg, true).Port; got != 22345 {
		t.Fatalf("explicit port request = %d, want 22345", got)
	}
}

func TestPostRemoteTailperfStartUnsupportedTarget(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	_, err := postRemoteTailperfStart(context.Background(), ts.URL, tailperfStartRequest{
		Protocol:       tailperf.ProtoTCP,
		DurationMillis: int64((5 * time.Second).Milliseconds()),
	})
	if err == nil {
		t.Fatal("postRemoteTailperfStart returned nil error for unsupported target")
	}
	if !strings.Contains(err.Error(), "does not support Magic Perf remote setup") {
		t.Fatalf("unsupported target error = %q", err)
	}
}

func TestTailperfLogPathFromCacheDir(t *testing.T) {
	got := tailperfLogPathFromCacheDir(filepath.Join("tmp", "cache"))
	want := filepath.Join("tmp", "cache", "tailscale", "tailperf.jsonl")
	if got != want {
		t.Fatalf("tailperfLogPathFromCacheDir = %q, want %q", got, want)
	}
}

func TestTailperfLogSinkWritesJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailperf.jsonl")
	sink := tailperfLogSinkForPath(path)
	want := tailperf.Result{
		SchemaVersion:        tailperf.SchemaVersion,
		Started:              time.Unix(1, 0),
		Ended:                time.Unix(2, 0),
		SourceNode:           "source",
		DestinationNode:      "dest",
		Direction:            tailperf.DirectionForward,
		Protocol:             tailperf.ProtoTCP,
		DurationMillis:       1000,
		TransferBytes:        1024,
		BitrateBitsPerSecond: 8192,
		Path:                 tailperf.PathMetadata{Type: tailperf.PathDirect},
	}
	if err := sink.LogTailperfResult(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := (tailperf.HistoryStore{Path: path}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len(history) = %d, want 1", len(got))
	}
	if got[0].SourceNode != want.SourceNode || got[0].DestinationNode != want.DestinationNode {
		t.Fatalf("history record = %+v, want source/dest from %+v", got[0], want)
	}
}

func TestTailperfLogSinkForConfig(t *testing.T) {
	explicit := filepath.Join(t.TempDir(), "custom.jsonl")
	path, sink, err := tailperfLogSinkForConfig(explicit, false)
	if err != nil {
		t.Fatal(err)
	}
	if path != explicit {
		t.Fatalf("log path = %q, want %q", path, explicit)
	}
	if sink == nil {
		t.Fatal("sink is nil")
	}

	path, sink, err = tailperfLogSinkForConfig(explicit, true)
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Fatalf("no-log path = %q, want empty", path)
	}
	if sink != nil {
		t.Fatal("no-log sink is non-nil")
	}
}

func TestWriteTailperfHistoryReportLimitsNewest(t *testing.T) {
	old := tailperf.Result{
		Started:              time.Unix(1, 0),
		SourceNode:           "node-a",
		DestinationNode:      "old-dest",
		Direction:            tailperf.DirectionForward,
		Protocol:             tailperf.ProtoTCP,
		TransferBytes:        1024,
		BitrateBitsPerSecond: 8192,
		Path:                 tailperf.PathMetadata{Type: tailperf.PathDERP, DERPRegionCode: "FRA"},
	}
	newest := old
	newest.Started = time.Unix(2, 0)
	newest.DestinationNode = "new-dest"
	newest.Path = tailperf.PathMetadata{Type: tailperf.PathDirect}

	var b bytes.Buffer
	if err := writeTailperfHistoryReport(&b, []tailperf.Result{old, newest}, 1); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Tailperf history", "new-dest", "direct"} {
		if !strings.Contains(out, want) {
			t.Fatalf("history output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "old-dest") {
		t.Fatalf("history limit included old result:\n%s", out)
	}
}

func TestWriteTailperfBaselineReport(t *testing.T) {
	base := tailperf.Result{
		SourceNode:           "node-a",
		DestinationNode:      "node-b",
		Direction:            tailperf.DirectionForward,
		Protocol:             tailperf.ProtoTCP,
		BitrateBitsPerSecond: 100,
		Path:                 tailperf.PathMetadata{Type: tailperf.PathDirect},
	}
	prior := []tailperf.Result{base, base, base}
	latest := base
	latest.BitrateBitsPerSecond = 40

	var b bytes.Buffer
	if err := writeTailperfBaselineReport(&b, tailperf.BuildNodePairInsight(latest, prior)); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Baseline", "below recent baseline", "Run a follow-up test"} {
		if !strings.Contains(out, want) {
			t.Fatalf("baseline output missing %q:\n%s", want, out)
		}
	}
}

func TestExportTailperfSupportHistoryRedacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailperf.jsonl")
	store := tailperf.HistoryStore{Path: path}
	if err := store.Append(context.Background(), tailperf.Result{
		SchemaVersion:        tailperf.SchemaVersion,
		Started:              time.Unix(1, 0),
		Ended:                time.Unix(2, 0),
		SourceNode:           "alice-laptop",
		DestinationNode:      "db.internal",
		Direction:            tailperf.DirectionForward,
		Protocol:             tailperf.ProtoTCP,
		DurationMillis:       1000,
		TransferBytes:        1024,
		BitrateBitsPerSecond: 8192,
		Path: tailperf.PathMetadata{
			Type:      tailperf.PathDirect,
			Endpoint:  "192.0.2.1:1234",
			PeerRelay: "203.0.113.5:443",
		},
	}); err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	if err := exportTailperfSupportHistory(context.Background(), path, "-", &b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, private := range []string{"alice-laptop", "db.internal", "192.0.2.1:1234", "203.0.113.5:443"} {
		if strings.Contains(out, private) {
			t.Fatalf("support export leaked %q:\n%s", private, out)
		}
	}
	for _, want := range []string{"redacted-source", "redacted-destination", `"redacted": true`} {
		if !strings.Contains(out, want) {
			t.Fatalf("support export missing %q:\n%s", want, out)
		}
	}
}
