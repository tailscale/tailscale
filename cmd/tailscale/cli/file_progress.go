// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_taildrop

package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/term"
	"tailscale.com/ipn"
)

// consentBatchProgress switches to per-file progress only after a file actually
// needs consent. Ordinary same-user sends retain the aggregate progress display.
type consentBatchProgress struct {
	mu           sync.Mutex
	files        []ipn.OutgoingFile // manifest order; names are escaped
	index        map[string]int
	active       bool
	ended        bool
	activated    chan struct{}
	completed    chan struct{}
	completeOnce sync.Once
	printed      map[string]string // last state printed in non-terminal output
}

func newConsentBatchProgress(manifest []ipn.OutgoingFile) *consentBatchProgress {
	b := &consentBatchProgress{
		files: slices.Clone(manifest), index: make(map[string]int),
		activated: make(chan struct{}), completed: make(chan struct{}),
		printed: make(map[string]string),
	}
	for i, f := range manifest {
		b.index[f.ID] = i
	}
	return b
}

func (b *consentBatchProgress) update(f *ipn.OutgoingFile) {
	b.mu.Lock()
	defer b.mu.Unlock()
	i, ok := b.index[f.ID]
	if !ok || b.files[i].Finished {
		return
	}
	old := b.files[i]
	b.files[i] = *f
	b.files[i].Name = old.Name
	b.files[i].DeclaredSize = old.DeclaredSize
	b.files[i].Sent = max(old.Sent, f.Sent)
	if f.Finished && b.files[i].CompletedAt.IsZero() {
		b.files[i].CompletedAt = time.Now()
	}
	if (f.WaitingForConsent || f.Declined) && !b.active {
		b.active = true
		close(b.activated)
	}
	for _, file := range b.files {
		if !file.Finished {
			return
		}
	}
	b.completeOnce.Do(func() { close(b.completed) })
}

func (b *consentBatchProgress) finish(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ended = true
	for i := range b.files {
		if b.files[i].CompletedAt.IsZero() {
			b.files[i].CompletedAt = time.Now()
		}
	}
	if success {
		for i := range b.files {
			b.files[i].Finished = true
			b.files[i].Succeeded = true
			b.files[i].WaitingForConsent = false
			b.files[i].Sent = b.files[i].DeclaredSize
		}
	}
}

// onlyDeclines reports whether the per-file display accounts for every result
// and all unsuccessful files were explicitly declined by the receiver.
func (b *consentBatchProgress) onlyDeclines() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	declined := false
	for _, f := range b.files {
		if !f.Finished || (!f.Succeeded && !f.Declined) {
			return false
		}
		declined = declined || f.Declined
	}
	return b.active && declined
}

func batchFileState(f ipn.OutgoingFile, ended bool) string {
	switch {
	case f.Finished && f.Succeeded:
		return "sent"
	case f.Finished && f.Declined:
		return "declined"
	case f.Finished:
		return "failed"
	case ended:
		return "completion not confirmed"
	case f.WaitingForConsent:
		return "waiting for approval"
	case f.Started.IsZero():
		return "queued"
	case f.Sent == 0:
		return "preparing"
	case f.Sent >= f.DeclaredSize:
		return "finishing"
	default:
		return "sending"
	}
}

func batchFileDetails(f ipn.OutgoingFile, now time.Time) string {
	if f.Started.IsZero() {
		return ""
	}
	end := now
	if !f.CompletedAt.IsZero() {
		end = f.CompletedAt
	}
	elapsed := max(0, end.Sub(f.Started)).Round(100 * time.Millisecond)
	sent := max(0, f.Sent)
	if f.DeclaredSize >= 0 {
		sent = min(sent, f.DeclaredSize)
		return fmt.Sprintf("%s / %s, %s elapsed", formatIEC(float64(sent), "B"), formatIEC(float64(f.DeclaredSize), "B"), elapsed)
	}
	return fmt.Sprintf("%s, %s elapsed", formatIEC(float64(sent), "B"), elapsed)
}

// printChanges emits named state transitions for pipes and --update-interval=0.
// Byte-level updates are left to the interactive renderer.
func (b *consentBatchProgress) printChanges(target string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.active {
		return
	}
	for _, f := range b.files {
		state := batchFileState(f, b.ended)
		if b.printed[f.ID] == state {
			continue
		}
		b.printed[f.ID] = state
		name, _ := url.PathUnescape(f.Name)
		if state == "waiting for approval" {
			state += " from " + target
		}
		if details := batchFileDetails(f, time.Now()); details != "" {
			state += " (" + details + ")"
		}
		fmt.Fprintf(Stderr, "%q: %s\n", name, state)
	}
}

func (b *consentBatchProgress) lines(width int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	lines := make([]string, 0, len(b.files))
	for _, f := range b.files {
		state := batchFileState(f, b.ended)
		if state == "sending" || state == "finishing" {
			sent := min(f.Sent, f.DeclaredSize)
			percent := 100.0
			if f.DeclaredSize > 0 {
				percent = 100 * float64(sent) / float64(f.DeclaredSize)
			}
			state = fmt.Sprintf("%s %.1f%%", state, percent)
		}
		if details := batchFileDetails(f, time.Now()); details != "" && width >= 80 {
			state += " (" + details + ")"
		}
		name, _ := url.PathUnescape(f.Name)
		// Quote filenames so control characters cannot corrupt the terminal. Limit
		// each row to one physical line so repainting keeps the cursor aligned.
		name = truncateString(fmt.Sprintf("%q", name), max(1, width-len(state)-3))
		lines = append(lines, truncateString(name+": "+state, max(1, width-1)))
	}
	return lines
}

func (b *consentBatchProgress) print(ctx context.Context, interval time.Duration, aggregate func(context.Context)) {
	aggregateCtx, stopAggregate := context.WithCancel(ctx)
	aggregateDone := make(chan struct{})
	go func() { defer close(aggregateDone); aggregate(aggregateCtx) }()
	select {
	case <-ctx.Done():
	case <-b.activated:
	}
	stopAggregate()
	<-aggregateDone
	select {
	case <-b.activated:
	default:
		return
	}
	// The aggregate printer finishes with a newline. Replace its final row
	// instead of leaving a stale "N files" status above the per-file display.
	fmt.Fprint(Stderr, "\x1b[1A")
	rows := 0
	paint := func() {
		width, _, err := term.GetSize(int(os.Stderr.Fd()))
		if err != nil {
			width = 80
		}
		lines := b.lines(width)
		if rows > 0 {
			fmt.Fprintf(Stderr, "\x1b[%dA", rows)
		}
		for _, line := range lines {
			fmt.Fprintf(Stderr, "\r\x1b[K%s\n", line)
		}
		rows = len(lines)
	}
	paint()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			paint()
			return
		case <-ticker.C:
			paint()
		}
	}
}
