// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_taildrop

package cli

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tstest"
)

// TestConsentBatchProgress verifies that consent switches a batch to per-file
// output; stale snapshots must not regress progress or resurrect completed
// transfers.
func TestConsentBatchProgress(t *testing.T) {
	var output bytes.Buffer
	tstest.Replace(t, &Stderr, io.Writer(&output))
	manifest := []ipn.OutgoingFile{
		{ID: "one", Name: url.PathEscape("a file%.txt"), DeclaredSize: 10},
		{ID: "two", Name: "b.txt", DeclaredSize: 10},
		{ID: "three", Name: "empty.txt", DeclaredSize: 0},
	}
	b := newConsentBatchProgress(manifest)
	first := manifest[0]
	first.Started = time.Now()
	b.update(&first)
	b.printChanges("laptop")
	if output.Len() != 0 {
		t.Fatal("ordinary transfer changed its display")
	}
	select {
	case <-b.activated:
		t.Fatal("ordinary transfer activated consent display")
	default:
	}

	first.WaitingForConsent = true
	b.update(&first)
	b.printChanges("laptop")
	if !strings.Contains(output.String(), `"a file%.txt": waiting for approval from laptop (0.00B / 10.00B,`) || !strings.Contains(output.String(), "elapsed)\n\"b.txt\": queued\n\"empty.txt\": queued\n") {
		t.Fatalf("initial states = %q", output.String())
	}
	output.Reset()
	b.printChanges("laptop")
	if output.Len() != 0 {
		t.Fatal("repeated snapshot repeated state output")
	}

	first.WaitingForConsent = false
	first.Finished = true
	first.Declined = true
	first.CompletedAt = first.Started.Add(2 * time.Second)
	b.update(&first)
	second := manifest[1]
	second.Started = time.Now()
	second.Sent = 5
	b.update(&second)
	// Stale snapshots must not resurrect a completed file or regress progress.
	first.Finished = false
	first.WaitingForConsent = true
	b.update(&first)
	second.Sent = 2
	b.update(&second)
	lines := b.lines(80)
	if len(lines) != 3 || !strings.Contains(lines[0], "declined (0.00B / 10.00B, 2s elapsed)") || !strings.Contains(lines[1], "\"b.txt\": sending 50.0%") || lines[2] != "\"empty.txt\": queued" {
		t.Fatalf("per-file states = %q", lines)
	}
	second.Finished, second.Succeeded = true, true
	second.Sent = 10
	second.CompletedAt = second.Started.Add(3 * time.Second)
	b.update(&second)
	third := manifest[2]
	third.Finished, third.Succeeded = true, true
	b.update(&third)
	select {
	case <-b.completed:
	default:
		t.Fatal("completion not signaled")
	}
	b.finish(false)
	b.printChanges("laptop")
	want := "\"a file%.txt\": declined (0.00B / 10.00B, 2s elapsed)\n\"b.txt\": sent (10.00B / 10.00B, 3s elapsed)\n\"empty.txt\": sent\n"
	if output.String() != want {
		t.Fatalf("final states = %q; want %q", output.String(), want)
	}
	if got := strings.Join(b.lines(80), "\n"); strings.Contains(got, "NaN") || strings.Contains(got, "waiting") {
		t.Fatalf("invalid final progress: %s", got)
	}
}

// TestConsentBatchProgressRenderer verifies that ordinary batches retain
// aggregate output, while consent rows escape filenames and fit the available
// terminal width.
func TestConsentBatchProgressRenderer(t *testing.T) {
	for _, consent := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "consent"}[consent], func(t *testing.T) {
			var output bytes.Buffer
			tstest.Replace(t, &Stderr, io.Writer(&output))
			b := newConsentBatchProgress([]ipn.OutgoingFile{{ID: "file", Name: url.PathEscape("a\nb.txt"), DeclaredSize: 0}})
			if consent {
				b.update(&ipn.OutgoingFile{ID: "file", WaitingForConsent: true})
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			called := false
			b.print(ctx, time.Hour, func(ctx context.Context) {
				called = true
				<-ctx.Done()
				io.WriteString(Stderr, "aggregate\n")
			})
			if !called {
				t.Fatal("existing progress printer wasn't used")
			}
			if !consent {
				if output.String() != "aggregate\n" {
					t.Fatalf("ordinary output changed: %q", output.String())
				}
			} else {
				if !strings.Contains(output.String(), `"a\nb.txt": waiting for approval`) {
					t.Fatalf("missing named consent state: %q", output.String())
				}
				for _, width := range []int{20, 40, 80} {
					for _, line := range b.lines(width) {
						if strings.ContainsAny(line, "\r\n\x1b") || len(line) > width+2 {
							t.Fatalf("invalid row for width %d: %q", width, line)
						}
					}
				}
			}
		})
	}
}

// TestBatchFileDetails verifies that completed transfers freeze elapsed time
// and distinguish declines from failures; active transfers keep updating their
// timing.
func TestBatchFileDetails(t *testing.T) {
	start := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	f := ipn.OutgoingFile{Started: start, CompletedAt: start.Add(2 * time.Second), Finished: true, Sent: 512, DeclaredSize: 1024}
	want := "512.00B / 1.00KiB, 2s elapsed"
	if got := batchFileDetails(f, start.Add(time.Hour)); got != want {
		t.Fatalf("finished timing keeps advancing: got %q, want %q", got, want)
	}
	if batchFileState(f, false) != "failed" {
		t.Fatal("generic failure mislabeled")
	}
	f.Declined = true
	if batchFileState(f, false) != "declined" {
		t.Fatal("decline mislabeled")
	}
	f.Finished, f.Declined = false, false
	f.CompletedAt = time.Time{}
	if got := batchFileDetails(f, start.Add(3*time.Second)); got != "512.00B / 1.00KiB, 3s elapsed" {
		t.Fatalf("active timing = %q", got)
	}
}
