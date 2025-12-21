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
	limiter := &Limiter[string]{
		Size:           2,
		Max:            10,
		RefillInterval: testRefillInterval,
	}

	// Consume entire burst
	now := time.Now().Truncate(testRefillInterval)
	allowed(t, limiter, "foo", 10, now)
	denied(t, limiter, "foo", 1, now)
	hasTokens(t, limiter, "foo", 0)

	allowed(t, limiter, "bar", 10, now)
	denied(t, limiter, "bar", 1, now)
	hasTokens(t, limiter, "bar", 0)

	// Refill 1 token for both foo and bar
	now = now.Add(time.Second + time.Millisecond)
	allowed(t, limiter, "foo", 1, now)
	denied(t, limiter, "foo", 1, now)
	hasTokens(t, limiter, "foo", 0)

	allowed(t, limiter, "bar", 1, now)
	denied(t, limiter, "bar", 1, now)
	hasTokens(t, limiter, "bar", 0)

	// Refill 2 tokens for foo and bar
	now = now.Add(2*time.Second + time.Millisecond)
	allowed(t, limiter, "foo", 2, now)
	denied(t, limiter, "foo", 1, now)
	hasTokens(t, limiter, "foo", 0)

	allowed(t, limiter, "bar", 2, now)
	denied(t, limiter, "bar", 1, now)
	hasTokens(t, limiter, "bar", 0)

	// qux can burst 10, evicts foo so it can immediately burst 10 again too
	allowed(t, limiter, "qux", 10, now)
	denied(t, limiter, "qux", 1, now)
	notInLimiter(t, limiter, "foo")
	denied(t, limiter, "bar", 1, now) // refresh bar so foo lookup doesn't evict it - still throttled

	allowed(t, limiter, "foo", 10, now)
	denied(t, limiter, "foo", 1, now)
	hasTokens(t, limiter, "foo", 0)
}

func TestLimiterOverdraft(t *testing.T) {
	// 1qps, burst of 10, overdraft of 2, 2 keys tracked
	limiter := &Limiter[string]{
		Size:           2,
		Max:            10,
		Overdraft:      2,
		RefillInterval: testRefillInterval,
	}

	// Consume entire burst, go 1 into debt
	now := time.Now().Truncate(testRefillInterval).Add(time.Millisecond)
	allowed(t, limiter, "foo", 10, now)
	denied(t, limiter, "foo", 1, now)
	hasTokens(t, limiter, "foo", -1)

	allowed(t, limiter, "bar", 10, now)
	denied(t, limiter, "bar", 1, now)
	hasTokens(t, limiter, "bar", -1)

	// Refill 1 token for both foo and bar.
	// Still denied, still in debt.
	now = now.Add(time.Second)
	denied(t, limiter, "foo", 1, now)
	hasTokens(t, limiter, "foo", -1)
	denied(t, limiter, "bar", 1, now)
	hasTokens(t, limiter, "bar", -1)

	// Refill 2 tokens for foo and bar (1 available after debt), try
	// to consume 4. Overdraft is capped to 2.
	now = now.Add(2 * time.Second)
	allowed(t, limiter, "foo", 1, now)
	denied(t, limiter, "foo", 3, now)
	hasTokens(t, limiter, "foo", -2)

	allowed(t, limiter, "bar", 1, now)
	denied(t, limiter, "bar", 3, now)
	hasTokens(t, limiter, "bar", -2)

	// Refill 1, not enough to allow.
	now = now.Add(time.Second)
	denied(t, limiter, "foo", 1, now)
	hasTokens(t, limiter, "foo", -2)
	denied(t, limiter, "bar", 1, now)
	hasTokens(t, limiter, "bar", -2)

	// qux evicts foo, foo can immediately burst 10 again.
	allowed(t, limiter, "qux", 1, now)
	hasTokens(t, limiter, "qux", 9)
	notInLimiter(t, limiter, "foo")
	allowed(t, limiter, "foo", 10, now)
	denied(t, limiter, "foo", 1, now)
	hasTokens(t, limiter, "foo", -1)
}

func TestDumpHTML(t *testing.T) {
	limiter := &Limiter[string]{
		Size:           3,
		Max:            10,
		Overdraft:      10,
		RefillInterval: testRefillInterval,
	}

	now := time.Now().Truncate(testRefillInterval).Add(time.Millisecond)
	allowed(t, limiter, "foo", 10, now)
	denied(t, limiter, "foo", 2, now)
	allowed(t, limiter, "bar", 4, now)
	allowed(t, limiter, "qux", 1, now)

	var out bytes.Buffer
	limiter.DumpHTML(&out, false)
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
	limiter.DumpHTML(&out, true)
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
	limiter.dumpHTML(&out, false, now)
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

func allowed(t *testing.T, limiter *Limiter[string], key string, count int, now time.Time) {
	t.Helper()
	for i := range count {
		if !limiter.allow(key, now) {
			toks, ok := limiter.tokensForTest(key)
			t.Errorf("after %d times: allow(%q, %q) = false, want true (%d tokens available, in cache = %v)", i, key, now, toks, ok)
		}
	}
}

func denied(t *testing.T, limiter *Limiter[string], key string, count int, now time.Time) {
	t.Helper()
	for i := range count {
		if limiter.allow(key, now) {
			toks, ok := limiter.tokensForTest(key)
			t.Errorf("after %d times: allow(%q, %q) = true, want false (%d tokens available, in cache = %v)", i, key, now, toks, ok)
		}
	}
}

func hasTokens(t *testing.T, limiter *Limiter[string], key string, want int64) {
	t.Helper()
	got, ok := limiter.tokensForTest(key)
	if !ok {
		t.Errorf("key %q missing from limiter", key)
	} else if got != want {
		t.Errorf("key %q has %d tokens, want %d", key, got, want)
	}
}

func notInLimiter(t *testing.T, limiter *Limiter[string], key string) {
	t.Helper()
	if tokens, ok := limiter.tokensForTest(key); ok {
		t.Errorf("key %q unexpectedly tracked by limiter, with %d tokens", key, tokens)
	}
}
