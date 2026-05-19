// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/tailperf"
)

func TestTailperfLogFileFlagRegistered(t *testing.T) {
	if perfCmd.FlagSet.Lookup("log-file") == nil {
		t.Fatal("tailscale perf missing --log-file flag")
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
