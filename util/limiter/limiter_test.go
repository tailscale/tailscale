// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package limiter

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

const testRefillInterval = time.Second

func TestLimiter(t *testing.T) {
	// 1qps, burst of 10, 2 keys tracked
	l := &Limiter[string]{
		Size:           2,
		Max:            10,
		RefillInterval: testRefillInterval,
	}

	// Consume entire burst
	now := time.Now().Truncate(testRefillInterval)
	allowed(t, l, "foo", 10, now)
	denied(t, l, "foo", 1, now)
	hasTokens(t, l, "foo", 0)

	allowed(t, l, "bar", 10, now)
	denied(t, l, "bar", 1, now)
	hasTokens(t, l, "bar", 0)

	// Refill 1 token for both foo and bar
	now = now.Add(time.Second + time.Millisecond)
	allowed(t, l, "foo", 1, now)
	denied(t, l, "foo", 1, now)
	hasTokens(t, l, "foo", 0)

	allowed(t, l, "bar", 1, now)
	denied(t, l, "bar", 1, now)
	hasTokens(t, l, "bar", 0)

	// Refill 2 tokens for foo and bar
	now = now.Add(2*time.Second + time.Millisecond)
	allowed(t, l, "foo", 2, now)
	denied(t, l, "foo", 1, now)
	hasTokens(t, l, "foo", 0)

	allowed(t, l, "bar", 2, now)
	denied(t, l, "bar", 1, now)
	hasTokens(t, l, "bar", 0)

	// qux can burst 10, evicts foo so it can immediately burst 10 again too
	allowed(t, l, "qux", 10, now)
	denied(t, l, "qux", 1, now)
	notInLimiter(t, l, "foo")
	denied(t, l, "bar", 1, now) // refresh bar so foo lookup doesn't evict it - still throttled

	allowed(t, l, "foo", 10, now)
	denied(t, l, "foo", 1, now)
	hasTokens(t, l, "foo", 0)
}

func TestLimiterOverdraft(t *testing.T) {
	// 1qps, burst of 10, overdraft of 2, 2 keys tracked
	l := &Limiter[string]{
		Size:           2,
		Max:            10,
		Overdraft:      2,
		RefillInterval: testRefillInterval,
	}

	// Consume entire burst, go 1 into debt
	now := time.Now().Truncate(testRefillInterval).Add(time.Millisecond)
	allowed(t, l, "foo", 10, now)
	denied(t, l, "foo", 1, now)
	hasTokens(t, l, "foo", -1)

	allowed(t, l, "bar", 10, now)
	denied(t, l, "bar", 1, now)
	hasTokens(t, l, "bar", -1)

	// Refill 1 token for both foo and bar.
	// Still denied, still in debt.
	now = now.Add(time.Second)
	denied(t, l, "foo", 1, now)
	hasTokens(t, l, "foo", -1)
	denied(t, l, "bar", 1, now)
	hasTokens(t, l, "bar", -1)

	// Refill 2 tokens for foo and bar (1 available after debt), try
	// to consume 4. Overdraft is capped to 2.
	now = now.Add(2 * time.Second)
	allowed(t, l, "foo", 1, now)
	denied(t, l, "foo", 3, now)
	hasTokens(t, l, "foo", -2)

	allowed(t, l, "bar", 1, now)
	denied(t, l, "bar", 3, now)
	hasTokens(t, l, "bar", -2)

	// Refill 1, not enough to allow.
	now = now.Add(time.Second)
	denied(t, l, "foo", 1, now)
	hasTokens(t, l, "foo", -2)
	denied(t, l, "bar", 1, now)
	hasTokens(t, l, "bar", -2)

	// qux evicts foo, foo can immediately burst 10 again.
	allowed(t, l, "qux", 1, now)
	hasTokens(t, l, "qux", 9)
	notInLimiter(t, l, "foo")
	allowed(t, l, "foo", 10, now)
	denied(t, l, "foo", 1, now)
	hasTokens(t, l, "foo", -1)
}

func TestDumpHTML(t *testing.T) {
	l := &Limiter[string]{
		Size:           3,
		Max:            10,
		Overdraft:      10,
		RefillInterval: testRefillInterval,
	}

	now := time.Now().Truncate(testRefillInterval).Add(time.Millisecond)
	allowed(t, l, "foo", 10, now)
	denied(t, l, "foo", 2, now)
	allowed(t, l, "bar", 4, now)
	allowed(t, l, "qux", 1, now)

	var out bytes.Buffer
	l.DumpHTML(&out, false)
	want := strings.Join([]string{
		"<table>",
		"<tr><th>Key</th><th>Tokens</th></tr>",
		"<tr><td>qux</td><td>9</td></tr>",
		"<tr><td>bar</td><td>6</td></tr>",
		"<tr><td>foo</td><td><b>-2</b></td></tr>",
		"</table>",
	}, "")
	if diff := cmp.Diff(out.String(), want); diff != "" {
		t.Fatalf("wrong DumpHTML output (-got+want):\n%s", diff)
	}

	out.Reset()
	l.DumpHTML(&out, true)
	want = strings.Join([]string{
		"<table>",
		"<tr><th>Key</th><th>Tokens</th></tr>",
		"<tr><td>foo</td><td>-2</td></tr>",
		"</table>",
	}, "")
	if diff := cmp.Diff(out.String(), want); diff != "" {
		t.Fatalf("wrong DumpHTML output (-got+want):\n%s", diff)
	}

	// Check that DumpHTML updates tokens even if the key wasn't hit
	// organically.
	now = now.Add(3 * time.Second)
	out.Reset()
	l.dumpHTML(&out, false, now)
	want = strings.Join([]string{
		"<table>",
		"<tr><th>Key</th><th>Tokens</th></tr>",
		"<tr><td>qux</td><td>10</td></tr>",
		"<tr><td>bar</td><td>9</td></tr>",
		"<tr><td>foo</td><td>1</td></tr>",
		"</table>",
	}, "")
	if diff := cmp.Diff(out.String(), want); diff != "" {
		t.Fatalf("wrong DumpHTML output (-got+want):\n%s", diff)
	}
}

func allowed(t *testing.T, l *Limiter[string], key string, count int, now time.Time) {
	t.Helper()
	for i := range count {
		if !l.allow(key, now) {
			toks, ok := l.tokensForTest(key)
			t.Errorf("after %d times: allow(%q, %q) = false, want true (%d tokens available, in cache = %v)", i, key, now, toks, ok)
		}
	}
}

func denied(t *testing.T, l *Limiter[string], key string, count int, now time.Time) {
	t.Helper()
	for i := range count {
		if l.allow(key, now) {
			toks, ok := l.tokensForTest(key)
			t.Errorf("after %d times: allow(%q, %q) = true, want false (%d tokens available, in cache = %v)", i, key, now, toks, ok)
		}
	}
}

func hasTokens(t *testing.T, l *Limiter[string], key string, want int64) {
	t.Helper()
	got, ok := l.tokensForTest(key)
	if !ok {
		t.Errorf("key %q missing from limiter", key)
	} else if got != want {
		t.Errorf("key %q has %d tokens, want %d", key, got, want)
	}
}

func notInLimiter(t *testing.T, l *Limiter[string], key string) {
	t.Helper()
	if tokens, ok := l.tokensForTest(key); ok {
		t.Errorf("key %q unexpectedly tracked by limiter, with %d tokens", key, tokens)
	}
}
