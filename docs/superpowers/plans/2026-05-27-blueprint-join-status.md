# Blueprint join/leave projection + `tailscale join status` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the projected `tailcfg.BlueprintConfig` in the CLI: rendered after a successful `tailscale join`, before a `tailscale leave`'s logout, and on demand via a new `tailscale join status` subcommand that also lists peers bound to the same blueprint when visible to the local node.

**Architecture:** Three commands (join / leave / join status) share one text renderer over `*tailcfg.BlueprintConfig`. A small plumbing change adds `BlueprintID` to `ipnstate.PeerStatus` so `join status` can filter peers by their binding. The wait-for-first-projection logic is extracted as a pure helper so the polling loop can be tested without a fake daemon.

**Tech Stack:** Go 1.23+. Tests use `testing` + `strings.Builder` capture; existing `cmd/tailscale/cli/*_test.go` patterns. Time control via injected interval/timeout constants.

**Spec:** `docs/superpowers/specs/2026-05-27-blueprint-join-status-design.md`

---

## File Structure

**New files:**

| File | Responsibility |
|---|---|
| `cmd/tailscale/cli/blueprint_render.go` | Pure formatter: `renderBlueprintConfig(w, id, cfg)` |
| `cmd/tailscale/cli/blueprint_render_test.go` | Formatter tests |
| `cmd/tailscale/cli/blueprint_wait.go` | Pure helper: `waitForBlueprintProjection(ctx, fetch, id, interval, timeout)` |
| `cmd/tailscale/cli/blueprint_wait_test.go` | Wait-loop tests |
| `cmd/tailscale/cli/join_status.go` | `tailscale join status` subcommand |
| `cmd/tailscale/cli/join_status_test.go` | Subcommand tests (text + JSON) |
| `cmd/tailscale/cli/leave_test.go` | New tests for `runLeave` (file does not exist today) |

**Modified files:**

| File | Change |
|---|---|
| `ipn/ipnstate/ipnstate.go` | Add `PeerStatus.BlueprintID` field; extend `AddPeer` merge |
| `ipn/ipnstate/ipnstate_test.go` | `AddPeer` merge test for the new field |
| `ipn/ipnlocal/local.go` | In `peerStatusFromNode`, copy `n.BlueprintID()` → `ps.BlueprintID` |
| `cmd/tailscale/cli/join.go` | After `StartLoginInteractive`, call wait helper + renderer; register subcommand |
| `cmd/tailscale/cli/leave.go` | Capture projection pre-logout; render after successful logout |

Each new CLI file is single-responsibility and ≤200 lines. The renderer and wait helper are deliberately pure functions (no `localClient`, no `os.Stdout`) so they're trivially testable. `join.go` and `leave.go` keep all IO; the helpers do not import `tailscale.com/internal/client/tailscale`.

---

## Task 1: Add `PeerStatus.BlueprintID` field + AddPeer merge

**Files:**
- Modify: `ipn/ipnstate/ipnstate.go:224-331` (PeerStatus struct), `:420-540` (AddPeer)
- Test: `ipn/ipnstate/ipnstate_test.go`

- [ ] **Step 1: Find the existing `TestAddPeer`-style test (if any) and pick a stable insertion point**

Run: `grep -n "func Test" ipn/ipnstate/ipnstate_test.go`
Note the existing tests so the new one slots in alphabetically or at the end of the file.

- [ ] **Step 2: Write the failing test**

Append to `ipn/ipnstate/ipnstate_test.go`:

```go
func TestAddPeerMergesBlueprintID(t *testing.T) {
	var sb StatusBuilder
	k := key.NewNode().Public()
	sb.AddPeer(k, &PeerStatus{HostName: "node-a", BlueprintID: "github-connector"})
	// Second AddPeer with empty BlueprintID must NOT overwrite the
	// non-empty value previously stored — same pattern as every other
	// string field in AddPeer.
	sb.AddPeer(k, &PeerStatus{HostName: "node-a"})

	got := sb.Status().Peer[k]
	if got == nil {
		t.Fatalf("peer missing from status")
	}
	if got.BlueprintID != "github-connector" {
		t.Errorf("BlueprintID = %q; want %q", got.BlueprintID, "github-connector")
	}

	// And a fresh non-empty value DOES overwrite.
	sb.AddPeer(k, &PeerStatus{HostName: "node-a", BlueprintID: "elsewhere"})
	got = sb.Status().Peer[k]
	if got.BlueprintID != "elsewhere" {
		t.Errorf("after overwrite, BlueprintID = %q; want %q", got.BlueprintID, "elsewhere")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./tool/go test ./ipn/ipnstate/ -run TestAddPeerMergesBlueprintID -v`
Expected: FAIL — `BlueprintID` field does not exist on `PeerStatus`.

- [ ] **Step 4: Add the field to `PeerStatus`**

In `ipn/ipnstate/ipnstate.go`, locate the `PeerStatus` struct definition. Add the new field directly after `Tags` (around line 246), keeping fields logically grouped (identity-then-binding):

```go
	// Tags are the list of ACL tags applied to this node.
	// See tailscale.com/tailcfg#Node.Tags for more information.
	Tags *views.Slice[string] `json:",omitempty"`

	// BlueprintID, if non-empty, is the Blueprint this node is bound to.
	// Populated from tailcfg.Node.BlueprintID. Empty for nodes that
	// were not brought up via `tailscale join`, and for blueprint-bound
	// peers whose BlueprintID is not visible to the local node per the
	// tailnet's policy.
	BlueprintID string `json:",omitempty"`
```

- [ ] **Step 5: Extend `AddPeer` to merge the field**

In `ipn/ipnstate/ipnstate.go`, in `AddPeer`, alongside the other `if v := st.HostName; v != ""` style blocks (around line 446-451), add:

```go
	if v := st.BlueprintID; v != "" {
		e.BlueprintID = v
	}
```

Insertion point: directly after the `HostName` block, before `DNSName`. (Matches alphabetical-ish grouping in the existing code; not a hard rule, just consistency.)

- [ ] **Step 6: Run test to verify it passes**

Run: `./tool/go test ./ipn/ipnstate/ -run TestAddPeerMergesBlueprintID -v`
Expected: PASS.

- [ ] **Step 7: Run the full package test to make sure nothing else broke**

Run: `./tool/go test ./ipn/ipnstate/...`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add ipn/ipnstate/ipnstate.go ipn/ipnstate/ipnstate_test.go
git commit -m "$(cat <<'EOF'
ipn/ipnstate: add PeerStatus.BlueprintID

Adds a BlueprintID field to PeerStatus and extends StatusBuilder.AddPeer
to merge it using the same "non-empty wins" pattern as every other
string field on the struct. The field is populated upstream (see the
peerStatusFromNode helper in ipn/ipnlocal/local.go) from
tailcfg.Node.BlueprintID, which is already on the wire as of capver
139, and is consumed by the `tailscale join status` subcommand to
filter peers by their blueprint binding.

Updates #cleanup

Signed-off-by: Kabir Sikand <kabir@tailscale.com>
EOF
)"
```

---

## Task 2: Plumb `Node.BlueprintID → PeerStatus.BlueprintID`

**Files:**
- Modify: `ipn/ipnlocal/local.go:1499-1524` (`peerStatusFromNode`)
- Test: `ipn/ipnlocal/blueprint_prefs_test.go` (extend) OR new minimal test

This is the single centralized place where peer + self status both get `tailcfg.NodeView` fields copied in. One line touches both code paths.

- [ ] **Step 1: Locate an existing test that already exercises `peerStatusFromNode` indirectly**

Run: `grep -rn "peerStatusFromNode\|UpdateStatus\|getStatus" ipn/ipnlocal/*_test.go | head`
Expected: there should be a status-builder test pattern. If none found, the new test will be self-contained.

- [ ] **Step 2: Write the failing test**

Create `ipn/ipnlocal/blueprint_peerstatus_test.go`:

```go
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// TestPeerStatusFromNodeCopiesBlueprintID verifies that peerStatusFromNode
// copies tailcfg.Node.BlueprintID into PeerStatus.BlueprintID. The same
// helper feeds both peer iteration (populatePeerStatusLocked) and the
// self-status mutator, so a single positive test covers both call sites.
func TestPeerStatusFromNodeCopiesBlueprintID(t *testing.T) {
	n := (&tailcfg.Node{
		ID:          1,
		StableID:    "stable-1",
		BlueprintID: "github-connector",
	}).View()
	var ps ipnstate.PeerStatus
	peerStatusFromNode(&ps, n)
	if ps.BlueprintID != "github-connector" {
		t.Errorf("BlueprintID = %q; want %q", ps.BlueprintID, "github-connector")
	}
}

// TestPeerStatusFromNodeEmptyBlueprintID verifies the non-bound case.
func TestPeerStatusFromNodeEmptyBlueprintID(t *testing.T) {
	n := (&tailcfg.Node{ID: 1, StableID: "stable-1"}).View()
	var ps ipnstate.PeerStatus
	peerStatusFromNode(&ps, n)
	if ps.BlueprintID != "" {
		t.Errorf("BlueprintID = %q; want empty", ps.BlueprintID)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./tool/go test ./ipn/ipnlocal/ -run TestPeerStatusFromNodeCopiesBlueprintID -v`
Expected: FAIL — current `peerStatusFromNode` does not touch `BlueprintID`.

- [ ] **Step 4: Add the field copy to `peerStatusFromNode`**

In `ipn/ipnlocal/local.go`, in `peerStatusFromNode` (around line 1499), add the field copy. Insertion point: right after `ps.ID = n.StableID()` to keep identity-ish fields together:

```go
func peerStatusFromNode(ps *ipnstate.PeerStatus, n tailcfg.NodeView) {
	ps.PublicKey = n.Key()
	ps.ID = n.StableID()
	ps.BlueprintID = n.BlueprintID()
	ps.Created = n.Created()
	// ... rest unchanged
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./tool/go test ./ipn/ipnlocal/ -run TestPeerStatusFromNode -v`
Expected: both new tests PASS.

- [ ] **Step 6: Run the full ipnlocal package to ensure no regression**

Run: `./tool/go test ./ipn/ipnlocal/...`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add ipn/ipnlocal/local.go ipn/ipnlocal/blueprint_peerstatus_test.go
git commit -m "$(cat <<'EOF'
ipn/ipnlocal: copy Node.BlueprintID into PeerStatus.BlueprintID

peerStatusFromNode is the centralized helper that copies fields from
tailcfg.NodeView into ipnstate.PeerStatus for both the local node
(via MutateSelfStatus) and every peer (via populatePeerStatusLocked).
A one-line copy populates the new PeerStatus.BlueprintID field added
in the previous commit, making blueprint bindings visible everywhere
the status surface is read.

Updates #cleanup

Signed-off-by: Kabir Sikand <kabir@tailscale.com>
EOF
)"
```

---

## Task 3: Pure renderer `renderBlueprintConfig`

**Files:**
- Create: `cmd/tailscale/cli/blueprint_render.go`
- Test: `cmd/tailscale/cli/blueprint_render_test.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/tailscale/cli/blueprint_render_test.go`:

```go
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

func TestRenderBlueprintConfig_NilCfg(t *testing.T) {
	var sb strings.Builder
	renderBlueprintConfig(&sb, "github-connector", nil)
	got := sb.String()
	want := "Blueprint:  bp:github-connector\n  (projection not yet received)\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRenderBlueprintConfig_AllBuckets(t *testing.T) {
	cfg := &tailcfg.BlueprintConfig{
		Tags:          []string{"tag:bp//github-connector", "tag:prod"},
		Routes:        []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.1.0/24")},
		ServeApps:     []string{"app:github"},
		ServeServices: []string{"svc:webhook"},
		ServeIPSets:   []string{"ipset:corp-internal"},
		Attrs:         []string{"nodeAttr:funnel"},
		Prefs:         []string{"pref:ssh", "pref:accept-routes"},
	}
	var sb strings.Builder
	renderBlueprintConfig(&sb, "github-connector", cfg)
	got := sb.String()
	want := "Blueprint:  bp:github-connector\n" +
		"  Tags:      tag:bp//github-connector, tag:prod\n" +
		"  Routes:    10.0.0.0/24, 10.0.1.0/24\n" +
		"  Apps:      app:github\n" +
		"  Services:  svc:webhook\n" +
		"  IPSets:    ipset:corp-internal\n" +
		"  Attrs:     nodeAttr:funnel\n" +
		"  Prefs:     pref:ssh, pref:accept-routes\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderBlueprintConfig_EmptyBucketsOmitted(t *testing.T) {
	cfg := &tailcfg.BlueprintConfig{
		Tags: []string{"tag:bp//foo"},
	}
	var sb strings.Builder
	renderBlueprintConfig(&sb, "foo", cfg)
	got := sb.String()
	want := "Blueprint:  bp:foo\n  Tags:      tag:bp//foo\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRenderBlueprintConfig_AllEmptyBuckets(t *testing.T) {
	cfg := &tailcfg.BlueprintConfig{}
	var sb strings.Builder
	renderBlueprintConfig(&sb, "foo", cfg)
	got := sb.String()
	want := "Blueprint:  bp:foo\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./tool/go test ./cmd/tailscale/cli/ -run TestRenderBlueprintConfig -v`
Expected: FAIL — `renderBlueprintConfig` undefined.

- [ ] **Step 3: Implement the renderer**

Create `cmd/tailscale/cli/blueprint_render.go`:

```go
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"tailscale.com/tailcfg"
)

// renderBlueprintConfig writes a human-readable description of cfg to
// w. The output is shared by `tailscale join`, `tailscale leave`, and
// `tailscale join status`; the shape is intentionally identical across
// the three so operators learn one layout. Empty buckets are omitted
// entirely (no "Apps: (none)" lines).
//
// cfg may be nil. A nil cfg indicates the local node is blueprint-bound
// (the caller has a known id) but the projection has not yet arrived
// via map poll; the renderer prints a single explanatory line in that
// case.
func renderBlueprintConfig(w io.Writer, id string, cfg *tailcfg.BlueprintConfig) {
	fmt.Fprintf(w, "Blueprint:  bp:%s\n", id)
	if cfg == nil {
		fmt.Fprintln(w, "  (projection not yet received)")
		return
	}
	writeBucket(w, "Tags", cfg.Tags)
	writeBucketPrefixes(w, "Routes", cfg.Routes)
	writeBucket(w, "Apps", cfg.ServeApps)
	writeBucket(w, "Services", cfg.ServeServices)
	writeBucket(w, "IPSets", cfg.ServeIPSets)
	writeBucket(w, "Attrs", cfg.Attrs)
	writeBucket(w, "Prefs", cfg.Prefs)
}

// blueprintLabelWidth is the column the comma-separated values land in.
// "Services:" is the longest label at 9 characters; we leave one space
// of padding, giving 10. Changing this shifts every value column.
const blueprintLabelWidth = 10

func writeBucket(w io.Writer, label string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(w, "  %-*s%s\n", blueprintLabelWidth, label+":", strings.Join(values, ", "))
}

func writeBucketPrefixes(w io.Writer, label string, values []netip.Prefix) {
	if len(values) == 0 {
		return
	}
	ss := make([]string, len(values))
	for i, v := range values {
		ss[i] = v.String()
	}
	fmt.Fprintf(w, "  %-*s%s\n", blueprintLabelWidth, label+":", strings.Join(ss, ", "))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./tool/go test ./cmd/tailscale/cli/ -run TestRenderBlueprintConfig -v`
Expected: all four tests PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/tailscale/cli/blueprint_render.go cmd/tailscale/cli/blueprint_render_test.go
git commit -m "$(cat <<'EOF'
cmd/tailscale/cli: add renderBlueprintConfig formatter

A pure formatter shared by `tailscale join`, `tailscale leave`, and
`tailscale join status`. Takes a blueprint id and an optional
*tailcfg.BlueprintConfig and writes an indented, label-aligned text
block describing the projected configuration. Empty buckets are
omitted; a nil cfg renders a "(projection not yet received)" line so
freshly-joined nodes get a sensible output before the first map poll.

Updates #cleanup

Signed-off-by: Kabir Sikand <kabir@tailscale.com>
EOF
)"
```

---

## Task 4: Pure wait helper `waitForBlueprintProjection`

**Files:**
- Create: `cmd/tailscale/cli/blueprint_wait.go`
- Test: `cmd/tailscale/cli/blueprint_wait_test.go`

The wait loop is extracted as a pure function taking an injectable status fetcher so we can test the timeout and success paths without a fake `localClient`.

- [ ] **Step 1: Write the failing test**

Create `cmd/tailscale/cli/blueprint_wait_test.go`:

```go
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// statusFn is the injectable fetcher type used by waitForBlueprintProjection.
type statusFn = func(context.Context) (*ipnstate.Status, error)

func TestWaitForBlueprintProjection_Success(t *testing.T) {
	calls := 0
	want := &tailcfg.BlueprintConfig{Tags: []string{"tag:bp//foo"}}
	fetch := func(ctx context.Context) (*ipnstate.Status, error) {
		calls++
		if calls < 3 {
			// First two calls: still starting.
			return &ipnstate.Status{
				BackendState: ipn.Starting.String(),
				Self:         &ipnstate.PeerStatus{},
			}, nil
		}
		// Third call: running, projection arrived.
		return &ipnstate.Status{
			BackendState: ipn.Running.String(),
			Self: &ipnstate.PeerStatus{
				BlueprintID:     "foo",
				BlueprintConfig: want,
			},
		}, nil
	}

	got, err := waitForBlueprintProjection(context.Background(), fetch, "foo", 1*time.Millisecond, 1*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("returned cfg = %p; want %p", got, want)
	}
	if calls < 3 {
		t.Errorf("expected at least 3 fetch calls; got %d", calls)
	}
}

func TestWaitForBlueprintProjection_Timeout(t *testing.T) {
	fetch := func(ctx context.Context) (*ipnstate.Status, error) {
		// Never advances past Starting.
		return &ipnstate.Status{
			BackendState: ipn.Starting.String(),
			Self:         &ipnstate.PeerStatus{},
		}, nil
	}
	_, err := waitForBlueprintProjection(context.Background(), fetch, "foo", 1*time.Millisecond, 10*time.Millisecond)
	if !errors.Is(err, errProjectionTimeout) {
		t.Errorf("err = %v; want errProjectionTimeout", err)
	}
}

func TestWaitForBlueprintProjection_MismatchedID(t *testing.T) {
	// Status is Running with a projection, but for a DIFFERENT blueprint
	// (stale netmap during a re-join). The helper must keep polling.
	calls := 0
	fetch := func(ctx context.Context) (*ipnstate.Status, error) {
		calls++
		return &ipnstate.Status{
			BackendState: ipn.Running.String(),
			Self: &ipnstate.PeerStatus{
				BlueprintID:     "stale",
				BlueprintConfig: &tailcfg.BlueprintConfig{},
			},
		}, nil
	}
	_, err := waitForBlueprintProjection(context.Background(), fetch, "fresh", 1*time.Millisecond, 5*time.Millisecond)
	if !errors.Is(err, errProjectionTimeout) {
		t.Errorf("err = %v; want errProjectionTimeout (mismatched id should not declare success)", err)
	}
	if calls < 2 {
		t.Errorf("expected multiple polls; got %d", calls)
	}
}

func TestWaitForBlueprintProjection_FetchError(t *testing.T) {
	// A status fetch error mid-loop is transient; keep polling until timeout.
	calls := 0
	fetch := func(ctx context.Context) (*ipnstate.Status, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("daemon not ready")
		}
		return &ipnstate.Status{
			BackendState: ipn.Running.String(),
			Self: &ipnstate.PeerStatus{
				BlueprintID:     "foo",
				BlueprintConfig: &tailcfg.BlueprintConfig{},
			},
		}, nil
	}
	cfg, err := waitForBlueprintProjection(context.Background(), fetch, "foo", 1*time.Millisecond, 1*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Error("cfg = nil; want non-nil")
	}
}

func TestWaitForBlueprintProjection_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fetch := func(ctx context.Context) (*ipnstate.Status, error) {
		return &ipnstate.Status{BackendState: ipn.Starting.String(), Self: &ipnstate.PeerStatus{}}, nil
	}
	_, err := waitForBlueprintProjection(ctx, fetch, "foo", 1*time.Millisecond, 1*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled", err)
	}
}
```

Note: this test references `PeerStatus.BlueprintConfig`. The wait helper reads the projection from there. We must add `BlueprintConfig *tailcfg.BlueprintConfig` to `PeerStatus` as part of this task — Self only, populated by `MutateSelfStatus`. (Peers don't carry projections; only the local node has its own projection.)

- [ ] **Step 2: Add `PeerStatus.BlueprintConfig` field**

In `ipn/ipnstate/ipnstate.go`, directly after the `BlueprintID` field added in Task 1:

```go
	// BlueprintConfig, if non-nil, is the local node's projected
	// Blueprint configuration. Populated only on Self (from
	// tailcfg.Node.BlueprintConfig); always nil on peer entries.
	BlueprintConfig *tailcfg.BlueprintConfig `json:",omitempty"`
```

And in `peerStatusFromNode` (`ipn/ipnlocal/local.go`, after the `ps.BlueprintID = ...` line):

```go
	if bc := n.BlueprintConfig(); bc.Valid() {
		ps.BlueprintConfig = bc.AsStruct()
	}
```

(For peer entries the caller may later clear this; we keep the copy path uniform. The renderer only reads `Status.Self.BlueprintConfig`, so leaking it onto peers is harmless. If we want strict containment, Task 5 can null it during `populatePeerStatusLocked` — but YAGNI.)

- [ ] **Step 3: Run tests to verify they still fail correctly (wait helper undefined)**

Run: `./tool/go test ./cmd/tailscale/cli/ -run TestWaitForBlueprintProjection -v`
Expected: FAIL — `waitForBlueprintProjection`, `errProjectionTimeout` undefined. (`PeerStatus.BlueprintConfig` should now exist.)

- [ ] **Step 4: Implement the wait helper**

Create `cmd/tailscale/cli/blueprint_wait.go`:

```go
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// errProjectionTimeout is returned by waitForBlueprintProjection when
// the deadline passes without the daemon reporting a matching
// projection. The caller treats this as success-of-binding +
// failure-of-display: the underlying join itself is unaffected.
var errProjectionTimeout = errors.New("blueprint projection not received before deadline")

// waitForBlueprintProjection polls fetch every interval until the
// daemon reports the node is Running with Self.BlueprintID == wantID
// and Self.BlueprintConfig != nil, or until timeout elapses, or until
// ctx is canceled.
//
// fetch errors are treated as transient: the function keeps polling
// until success or timeout. ctx cancellation propagates out
// immediately.
//
// This function exists separate from runJoin so the wait-loop
// behavior can be tested without a fake LocalClient.
func waitForBlueprintProjection(ctx context.Context, fetch func(context.Context) (*ipnstate.Status, error), wantID string, interval, timeout time.Duration) (*tailcfg.BlueprintConfig, error) {
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		st, err := fetch(ctx)
		if err == nil && st != nil && st.BackendState == ipn.Running.String() &&
			st.Self != nil && st.Self.BlueprintID == wantID && st.Self.BlueprintConfig != nil {
			return st.Self.BlueprintConfig, nil
		}
		if time.Now().After(deadline) {
			return nil, errProjectionTimeout
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
		}
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./tool/go test ./cmd/tailscale/cli/ -run TestWaitForBlueprintProjection -v`
Expected: all five tests PASS.

- [ ] **Step 6: Run downstream packages too — `PeerStatus.BlueprintConfig` change touches the type**

Run: `./tool/go build ./... && ./tool/go test ./ipn/...`
Expected: builds; ipn tests pass. If `peerStatusFromNode` test in Task 2 starts asserting `BlueprintConfig == nil` for the non-bound case, extend that test to also exercise the bound case here. (Quick add — keep the test in `ipn/ipnlocal/blueprint_peerstatus_test.go`.)

- [ ] **Step 7: Commit**

```bash
git add cmd/tailscale/cli/blueprint_wait.go cmd/tailscale/cli/blueprint_wait_test.go ipn/ipnstate/ipnstate.go ipn/ipnlocal/local.go
git commit -m "$(cat <<'EOF'
cmd/tailscale/cli, ipn/ipnstate: add blueprint projection wait helper

Adds a pure waitForBlueprintProjection helper that polls a Status
fetcher until the daemon reports a matching projection or a deadline
elapses. Extracted from runJoin so the wait-loop behavior can be unit
tested without a fake LocalClient.

Also threads PeerStatus.BlueprintConfig (populated only on Self, from
tailcfg.Node.BlueprintConfig) so the helper's success condition can
be expressed in terms of the public Status surface. Peer entries
never read this field; the helper checks only Status.Self.

Updates #cleanup

Signed-off-by: Kabir Sikand <kabir@tailscale.com>
EOF
)"
```

---

## Task 5: Wire wait helper into `runJoin`

**Files:**
- Modify: `cmd/tailscale/cli/join.go:228-249` (post-Start block)

- [ ] **Step 1: Add a metric constant + wait-loop tunables at top of join.go**

In `cmd/tailscale/cli/join.go`, add to the existing metric block (around lines 20-33):

```go
// metricBlueprintJoinProjectionTimeout counts join invocations where
// the binding succeeded but the wait-for-first-projection loop exited
// without seeing Node.BlueprintConfig. The join itself is unaffected;
// only the display deadline lapsed.
var metricBlueprintJoinProjectionTimeout = clientmetric.NewCounter("cli_blueprint_join_projection_timeout")
```

And below the existing imports, add:

```go
// Wait-loop tunables. Package-level so tests can override before
// invoking runJoin in-process if needed.
var (
	joinProjectionPollInterval = 250 * time.Millisecond
	joinProjectionPollTimeout  = 30 * time.Second
)
```

Update the import block to add `"time"`.

- [ ] **Step 2: Replace the trailing print in `runJoin`**

The current tail of `runJoin` is (lines 245-249):

```go
	metricBlueprintJoinSuccess.Add(1)
	metricBlueprintBound.Set(1)
	fmt.Printf("Bound to blueprint bp:%s\n", id)
	return nil
}
```

Replace with:

```go
	metricBlueprintJoinSuccess.Add(1)
	metricBlueprintBound.Set(1)
	fmt.Printf("Bound to blueprint bp:%s.\n", id)

	// Block briefly for the first map poll so the operator sees what
	// the blueprint actually projected onto this node. The binding
	// itself has succeeded; if the projection takes longer than the
	// deadline, fall back to a pointer to `tailscale join status`.
	cfg, err := waitForBlueprintProjection(ctx, localClient.Status, id, joinProjectionPollInterval, joinProjectionPollTimeout)
	if errors.Is(err, errProjectionTimeout) {
		metricBlueprintJoinProjectionTimeout.Add(1)
		fmt.Println("Projection not yet received; run 'tailscale join status' to see it.")
		return nil
	}
	if err != nil {
		// Context canceled or other unexpected error. Still treat the
		// join as successful (which it is — the binding landed), but
		// surface the failure so the operator can re-run `tailscale
		// join status` themselves.
		fmt.Printf("Projection wait failed: %v\n", err)
		return nil
	}
	renderBlueprintConfig(os.Stdout, id, cfg)
	return nil
}
```

Update the import block: add `"os"` if not present.

- [ ] **Step 3: Build to make sure compilation works**

Run: `./tool/go build ./cmd/tailscale/...`
Expected: success.

- [ ] **Step 4: Run the existing join tests to make sure nothing regressed**

Run: `./tool/go test ./cmd/tailscale/cli/ -run TestResolveBlueprintArg -v`
Expected: PASS — these tests don't touch the wait path, so they should be untouched.

- [ ] **Step 5: Commit**

```bash
git add cmd/tailscale/cli/join.go
git commit -m "$(cat <<'EOF'
cmd/tailscale/cli: render blueprint projection after `tailscale join`

After a successful join, poll the daemon's Status for up to 30s
waiting for the first map poll to deliver Node.BlueprintConfig, then
print the projection via the shared renderer. On timeout, fall back
to a pointer to `tailscale join status` so the operator knows where
to look. The binding itself is unaffected by the wait outcome; only
the display deadline matters.

Adds cli_blueprint_join_projection_timeout to record the timeout-only
case for observability; metricBlueprintJoinSuccess fires regardless
since the join succeeded.

Updates #cleanup

Signed-off-by: Kabir Sikand <kabir@tailscale.com>
EOF
)"
```

---

## Task 6: `tailscale join status` subcommand

**Files:**
- Create: `cmd/tailscale/cli/join_status.go`
- Create: `cmd/tailscale/cli/join_status_test.go`
- Modify: `cmd/tailscale/cli/join.go` (subcommand registration)

- [ ] **Step 1: Write the failing test (renderer-level)**

Create `cmd/tailscale/cli/join_status_test.go`:

```go
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func mkPeer(host, bpID string, ip string) (key.NodePublic, *ipnstate.PeerStatus) {
	ps := &ipnstate.PeerStatus{
		HostName:    host,
		BlueprintID: bpID,
	}
	if ip != "" {
		ps.TailscaleIPs = []netip.Addr{netip.MustParseAddr(ip)}
	}
	return key.NewNode().Public(), ps
}

func TestRenderJoinStatus_NotBound(t *testing.T) {
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self:         &ipnstate.PeerStatus{},
	}
	var sb strings.Builder
	rc := renderJoinStatus(&sb, st)
	if rc != 1 {
		t.Errorf("returncode = %d; want 1", rc)
	}
	if !strings.Contains(sb.String(), "not blueprint-bound") {
		t.Errorf("output missing 'not blueprint-bound'; got:\n%s", sb.String())
	}
}

func TestRenderJoinStatus_BoundWithPeers(t *testing.T) {
	k1, p1 := mkPeer("node-a", "github-connector", "100.64.0.5")
	k2, p2 := mkPeer("node-b", "github-connector", "100.64.0.7")
	k3, p3 := mkPeer("other", "different", "100.64.0.99")
	k4, p4 := mkPeer("nobinding", "", "100.64.0.100")
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self: &ipnstate.PeerStatus{
			BlueprintID: "github-connector",
			BlueprintConfig: &tailcfg.BlueprintConfig{
				Tags: []string{"tag:bp//github-connector"},
			},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			k1: p1, k2: p2, k3: p3, k4: p4,
		},
	}
	var sb strings.Builder
	rc := renderJoinStatus(&sb, st)
	if rc != 0 {
		t.Errorf("returncode = %d; want 0", rc)
	}
	out := sb.String()
	if !strings.Contains(out, "Blueprint:  bp:github-connector") {
		t.Errorf("missing projection header; got:\n%s", out)
	}
	if !strings.Contains(out, "Tags:      tag:bp//github-connector") {
		t.Errorf("missing tags line; got:\n%s", out)
	}
	if !strings.Contains(out, "Peers bound to bp:github-connector (2 visible)") {
		t.Errorf("missing peer count; got:\n%s", out)
	}
	if !strings.Contains(out, "node-a") || !strings.Contains(out, "node-b") {
		t.Errorf("missing peer hostnames; got:\n%s", out)
	}
	if strings.Contains(out, "other") || strings.Contains(out, "nobinding") {
		t.Errorf("output includes peers with a different/empty BlueprintID; got:\n%s", out)
	}
	// Hostname sort order: node-a before node-b.
	if i, j := strings.Index(out, "node-a"), strings.Index(out, "node-b"); i < 0 || j < 0 || i > j {
		t.Errorf("peers not sorted by hostname; got:\n%s", out)
	}
}

func TestRenderJoinStatus_BoundNoPeers(t *testing.T) {
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self: &ipnstate.PeerStatus{
			BlueprintID:     "lonely",
			BlueprintConfig: &tailcfg.BlueprintConfig{},
		},
	}
	var sb strings.Builder
	rc := renderJoinStatus(&sb, st)
	if rc != 0 {
		t.Errorf("returncode = %d; want 0", rc)
	}
	if !strings.Contains(sb.String(), "No other peers bound to bp:lonely are visible") {
		t.Errorf("missing no-peers message; got:\n%s", sb.String())
	}
}

func TestRenderJoinStatus_BoundProjectionNil(t *testing.T) {
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self: &ipnstate.PeerStatus{
			BlueprintID:     "foo",
			BlueprintConfig: nil,
		},
	}
	var sb strings.Builder
	rc := renderJoinStatus(&sb, st)
	if rc != 0 {
		t.Errorf("returncode = %d; want 0", rc)
	}
	if !strings.Contains(sb.String(), "(projection not yet received)") {
		t.Errorf("missing projection-pending line; got:\n%s", sb.String())
	}
}

func TestRenderJoinStatusJSON(t *testing.T) {
	k1, p1 := mkPeer("node-a", "foo", "100.64.0.5")
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self: &ipnstate.PeerStatus{
			BlueprintID:     "foo",
			BlueprintConfig: &tailcfg.BlueprintConfig{Tags: []string{"tag:bp//foo"}},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{k1: p1},
	}
	var sb strings.Builder
	rc := renderJoinStatusJSON(&sb, st)
	if rc != 0 {
		t.Errorf("returncode = %d; want 0", rc)
	}
	var out joinStatusJSON
	if err := json.Unmarshal([]byte(sb.String()), &out); err != nil {
		t.Fatalf("invalid JSON: %v\noutput: %s", err, sb.String())
	}
	if out.BlueprintID != "foo" {
		t.Errorf("BlueprintID = %q; want %q", out.BlueprintID, "foo")
	}
	if out.BlueprintConfig == nil || len(out.BlueprintConfig.Tags) != 1 {
		t.Errorf("BlueprintConfig.Tags = %v; want one entry", out.BlueprintConfig)
	}
	if len(out.BoundPeers) != 1 || out.BoundPeers[0].HostName != "node-a" {
		t.Errorf("BoundPeers = %+v; want one entry for node-a", out.BoundPeers)
	}
}

func TestRenderJoinStatusJSON_NotBound(t *testing.T) {
	st := &ipnstate.Status{Self: &ipnstate.PeerStatus{}}
	var sb strings.Builder
	rc := renderJoinStatusJSON(&sb, st)
	if rc != 1 {
		t.Errorf("returncode = %d; want 1", rc)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./tool/go test ./cmd/tailscale/cli/ -run TestRenderJoinStatus -v`
Expected: FAIL — `renderJoinStatus`, `renderJoinStatusJSON`, `joinStatusJSON` undefined.

- [ ] **Step 3: Implement the subcommand**

Create `cmd/tailscale/cli/join_status.go`:

```go
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

var joinStatusArgs struct {
	json bool
}

var joinStatusCmd = &ffcli.Command{
	Name:       "status",
	ShortUsage: "tailscale join status [--json]",
	ShortHelp:  "Show the projected blueprint configuration on this node",
	LongHelp: strings.TrimSpace(`
"tailscale join status" displays the configuration projected onto
this node by its bound Blueprint, plus the set of peers visible to
this node that are bound to the same Blueprint.

Peer visibility is determined by the tailnet's policy; peers whose
binding is not visible to this node will not appear in the output.
"No other peers bound to bp:<id> are visible to this node." means
just that -- it does not mean there are no other bound peers.
`),
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("join status")
		fs.BoolVar(&joinStatusArgs.json, "json", false, "output in JSON format (WARNING: format subject to change)")
		return fs
	})(),
	Exec: runJoinStatus,
}

// joinStatusJSON is the documented (but unstable) JSON shape.
type joinStatusJSON struct {
	BlueprintID     string                   `json:"BlueprintID"`
	BlueprintConfig *tailcfg.BlueprintConfig `json:"BlueprintConfig,omitempty"`
	BoundPeers      []boundPeerJSON          `json:"BoundPeers"`
}

type boundPeerJSON struct {
	HostName     string       `json:"HostName"`
	TailscaleIPs []netip.Addr `json:"TailscaleIPs"`
}

func runJoinStatus(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unexpected positional arguments: %q", args)
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	var rc int
	if joinStatusArgs.json {
		rc = renderJoinStatusJSON(os.Stdout, st)
	} else {
		rc = renderJoinStatus(os.Stdout, st)
	}
	if rc != 0 {
		os.Exit(rc)
	}
	return nil
}

// renderJoinStatus writes the text representation of st's blueprint
// state to w and returns a process exit code (0 ok, 1 not-bound).
// Pure: no I/O beyond w.
func renderJoinStatus(w io.Writer, st *ipnstate.Status) int {
	if st == nil || st.Self == nil || st.Self.BlueprintID == "" {
		fmt.Fprintln(w, "this node is not blueprint-bound; run 'tailscale join --blueprint=<id> --auth-key=...' to bind it")
		return 1
	}
	id := st.Self.BlueprintID
	renderBlueprintConfig(w, id, st.Self.BlueprintConfig)

	// Collect peers bound to the same blueprint.
	type peerRow struct {
		host string
		ip   string
	}
	var rows []peerRow
	for _, p := range st.Peer {
		if p == nil || p.BlueprintID != id {
			continue
		}
		ip := ""
		if len(p.TailscaleIPs) > 0 {
			ip = p.TailscaleIPs[0].String()
		}
		rows = append(rows, peerRow{host: p.HostName, ip: ip})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].host < rows[j].host })

	if len(rows) == 0 {
		fmt.Fprintf(w, "No other peers bound to bp:%s are visible to this node.\n", id)
		return 0
	}
	fmt.Fprintf(w, "Peers bound to bp:%s (%d visible):\n", id, len(rows))
	for _, r := range rows {
		fmt.Fprintf(w, "  %-12s %s\n", r.host, r.ip)
	}
	return 0
}

func renderJoinStatusJSON(w io.Writer, st *ipnstate.Status) int {
	if st == nil || st.Self == nil || st.Self.BlueprintID == "" {
		// Match the text exit-code behavior. Still emit a small JSON
		// object so scripted callers can distinguish empty-but-parseable
		// from connect failure.
		json.NewEncoder(w).Encode(joinStatusJSON{})
		return 1
	}
	out := joinStatusJSON{
		BlueprintID:     st.Self.BlueprintID,
		BlueprintConfig: st.Self.BlueprintConfig,
		BoundPeers:      []boundPeerJSON{},
	}
	for _, p := range st.Peer {
		if p == nil || p.BlueprintID != st.Self.BlueprintID {
			continue
		}
		out.BoundPeers = append(out.BoundPeers, boundPeerJSON{
			HostName:     p.HostName,
			TailscaleIPs: p.TailscaleIPs,
		})
	}
	sort.Slice(out.BoundPeers, func(i, j int) bool {
		return out.BoundPeers[i].HostName < out.BoundPeers[j].HostName
	})
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
	return 0
}

// _ silences ipn package import if no symbols end up used in this file;
// retained because BackendState comparisons may be needed in future.
var _ = ipn.Running
```

- [ ] **Step 4: Register the subcommand on `joinCmd`**

In `cmd/tailscale/cli/join.go`, after the `joinCmd` definition (around line 93), add a small init function or set the field at variable declaration. Simplest: change `joinCmd` declaration tail. Currently:

```go
var joinCmd = &ffcli.Command{
	Name:       "join",
	...
	FlagSet: joinFlagSet,
	Exec: func(ctx context.Context, args []string) error {
		return runJoin(ctx, args, &joinArgs)
	},
}
```

Add right after the closing brace:

```go
func init() {
	joinCmd.Subcommands = []*ffcli.Command{joinStatusCmd}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./tool/go test ./cmd/tailscale/cli/ -run TestRenderJoinStatus -v`
Expected: all six tests PASS.

- [ ] **Step 6: Build and quick smoke**

Run: `./tool/go build ./cmd/tailscale/...`
Expected: success.

Run: `./tool/go run ./cmd/tailscale join status 2>&1 | head -5`
Expected: either "this node is not blueprint-bound..." or a real projection — both are acceptable. (If `tailscaled` is not running, the call returns `fixTailscaledConnectError`'s message; that's fine for this smoke check.)

- [ ] **Step 7: Commit**

```bash
git add cmd/tailscale/cli/join.go cmd/tailscale/cli/join_status.go cmd/tailscale/cli/join_status_test.go
git commit -m "$(cat <<'EOF'
cmd/tailscale/cli: add `tailscale join status` subcommand

Adds an inspection subcommand under `tailscale join` that renders
the projected BlueprintConfig for the local node plus the list of
peers visible to this node bound to the same Blueprint. Supports
--json for scripting; the JSON shape mirrors `tailscale status
--json`'s "may change between releases" contract.

Peer visibility tracks the tailnet's policy: peers whose binding is
not visible to this node simply do not appear. The output uses the
phrase "visible to this node" deliberately -- absence in the list is
not absence in the tailnet.

Updates #cleanup

Signed-off-by: Kabir Sikand <kabir@tailscale.com>
EOF
)"
```

---

## Task 7: Render projection in `tailscale leave`

**Files:**
- Modify: `cmd/tailscale/cli/leave.go`
- Create: `cmd/tailscale/cli/leave_test.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/tailscale/cli/leave_test.go`:

```go
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func TestRenderLeaveMessage_Bound(t *testing.T) {
	cfg := &tailcfg.BlueprintConfig{
		Tags:      []string{"tag:bp//foo"},
		ServeApps: []string{"app:github"},
	}
	var sb strings.Builder
	renderLeaveMessage(&sb, "foo", cfg)
	out := sb.String()
	if !strings.Contains(out, "Detached from blueprint bp:foo") {
		t.Errorf("missing detach line; got:\n%s", out)
	}
	if !strings.Contains(out, "Released:") {
		t.Errorf("missing 'Released:' header; got:\n%s", out)
	}
	if !strings.Contains(out, "Tags:      tag:bp//foo") {
		t.Errorf("missing projection content; got:\n%s", out)
	}
}

func TestRenderLeaveMessage_BoundNilProjection(t *testing.T) {
	var sb strings.Builder
	renderLeaveMessage(&sb, "foo", nil)
	out := sb.String()
	if out != "Detached from blueprint bp:foo and logged out.\n" {
		t.Errorf("unexpected output:\n%q", out)
	}
}

func TestRenderLeaveMessage_NotBound(t *testing.T) {
	var sb strings.Builder
	renderLeaveMessage(&sb, "", nil)
	out := sb.String()
	if out != "Logged out. (Node was not blueprint-bound.)\n" {
		t.Errorf("unexpected output:\n%q", out)
	}
}

// Helper accessor for the status-snapshot extraction logic used by
// runLeave. Verifies it pulls BlueprintConfig from Self when present.
func TestSnapshotProjectionFromStatus(t *testing.T) {
	want := &tailcfg.BlueprintConfig{Tags: []string{"x"}}
	st := &ipnstate.Status{
		Self: &ipnstate.PeerStatus{
			BlueprintID:     "foo",
			BlueprintConfig: want,
		},
	}
	got := snapshotProjection(st)
	if got != want {
		t.Errorf("snapshotProjection = %p; want %p", got, want)
	}

	if snapshotProjection(nil) != nil {
		t.Error("nil status should return nil")
	}
	if snapshotProjection(&ipnstate.Status{}) != nil {
		t.Error("status with nil Self should return nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./tool/go test ./cmd/tailscale/cli/ -run TestRenderLeaveMessage -v`
Expected: FAIL — `renderLeaveMessage`, `snapshotProjection` undefined.

- [ ] **Step 3: Refactor `leave.go` to extract pure helpers and call them from `runLeave`**

Replace the contents of `cmd/tailscale/cli/leave.go` with:

```go
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
)

// metricBlueprintLeave counts `tailscale leave` invocations,
// regardless of outcome.
var metricBlueprintLeave = clientmetric.NewCounter("cli_blueprint_leave")

var leaveCmd = &ffcli.Command{
	Name:       "leave",
	ShortUsage: "tailscale leave",
	ShortHelp:  "Detach this node from its Blueprint and log out",
	LongHelp: `"tailscale leave" detaches a node that was brought up via
"tailscale join" from its bound Blueprint and logs the node out.
Blueprint-bound nodes are ephemeral; once detached, the node is
deleted from the tailnet server-side and any local registration
state is discarded. A subsequent "tailscale join" mints a fresh
node from scratch.

If the node is not blueprint-bound, "tailscale leave" still logs
the node out (same behavior as "tailscale logout") and emits a
note.`,
	FlagSet: newFlagSet("leave"),
	Exec: func(ctx context.Context, args []string) error {
		return runLeave(ctx, args)
	},
}

// snapshotProjection returns the local node's BlueprintConfig from a
// Status snapshot, or nil if the status is missing or not bound.
// Pure helper for test isolation.
func snapshotProjection(st *ipnstate.Status) *tailcfg.BlueprintConfig {
	if st == nil || st.Self == nil {
		return nil
	}
	return st.Self.BlueprintConfig
}

// renderLeaveMessage writes the post-logout message to w.
//   - id == "": node was not blueprint-bound.
//   - id != "" && cfg == nil: bound but projection unavailable (fallback).
//   - id != "" && cfg != nil: bound; print the released projection.
func renderLeaveMessage(w io.Writer, id string, cfg *tailcfg.BlueprintConfig) {
	if id == "" {
		fmt.Fprintln(w, "Logged out. (Node was not blueprint-bound.)")
		return
	}
	if cfg == nil {
		fmt.Fprintf(w, "Detached from blueprint bp:%s and logged out.\n", id)
		return
	}
	fmt.Fprintf(w, "Detached from blueprint bp:%s. Released:\n", id)
	renderBlueprintConfig(w, id, cfg)
}

// runLeave logs out the current node. If the node is blueprint-bound,
// it first captures the projection (for display), then clears
// Prefs.BlueprintID so the lock-out on subsequent "tailscale set"
// calls is released even if the user reuses the state directory.
func runLeave(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unexpected positional arguments: %q", args)
	}
	metricBlueprintLeave.Add(1)

	curPrefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("reading prefs: %w", err)
	}
	wasBound := curPrefs != nil && curPrefs.IsBlueprintBound()
	boundTo := ""
	var cfg *tailcfg.BlueprintConfig
	if wasBound {
		boundTo = curPrefs.BlueprintID
		// Best-effort: capture the projection before tearing down. If
		// Status fails or hasn't arrived yet, fall back to the short
		// message. Leave is reversible; don't block on the snapshot.
		if st, err := localClient.Status(ctx); err == nil {
			cfg = snapshotProjection(st)
		}
		// Clear the binding marker first so a crash between
		// EditPrefs and Logout still leaves the node in a sensible
		// "not blueprint-bound" state.
		if _, err := localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs:          ipn.Prefs{BlueprintID: ""},
			BlueprintIDSet: true,
		}); err != nil {
			return fmt.Errorf("clearing blueprint binding: %w", err)
		}
	}

	if err := localClient.Logout(ctx); err != nil {
		return fmt.Errorf("logging out: %w", err)
	}
	metricBlueprintBound.Set(0)
	renderLeaveMessage(os.Stdout, boundTo, cfg)
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./tool/go test ./cmd/tailscale/cli/ -run "TestRenderLeaveMessage|TestSnapshotProjectionFromStatus" -v`
Expected: all four tests PASS.

- [ ] **Step 5: Run the full CLI test package to catch regressions**

Run: `./tool/go test ./cmd/tailscale/cli/...`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/tailscale/cli/leave.go cmd/tailscale/cli/leave_test.go
git commit -m "$(cat <<'EOF'
cmd/tailscale/cli: render blueprint projection on `tailscale leave`

Before clearing Prefs.BlueprintID and logging out, capture the
current Status.Self.BlueprintConfig and display it after the logout
completes so the operator can see what configuration the node is
releasing. Best-effort: if the Status fetch fails or the projection
hasn't arrived yet, fall back to the short "Detached from blueprint
bp:<id> and logged out." line. Leave is reversible; we do not block
on a Status fetch.

Extracts two pure helpers (snapshotProjection, renderLeaveMessage)
so the display branches are unit-testable without a live daemon.

Updates #cleanup

Signed-off-by: Kabir Sikand <kabir@tailscale.com>
EOF
)"
```

---

## Task 8: Integration sanity check

**Files:** None. Pure verification.

- [ ] **Step 1: Run the full test suite for the touched packages**

Run: `./tool/go test ./cmd/tailscale/cli/... ./ipn/ipnstate/... ./ipn/ipnlocal/...`
Expected: all PASS. Note any flaky / pre-existing failures.

- [ ] **Step 2: Run `make pr`-equivalent checks (OSS repo only does a subset of corp's `make pr`)**

Run: `./tool/go vet ./cmd/tailscale/cli/... ./ipn/ipnstate/... ./ipn/ipnlocal/...`
Expected: clean.

Run: `gofmt -l cmd/tailscale/cli/blueprint_render.go cmd/tailscale/cli/blueprint_wait.go cmd/tailscale/cli/join_status.go cmd/tailscale/cli/leave.go cmd/tailscale/cli/join.go ipn/ipnstate/ipnstate.go ipn/ipnlocal/local.go`
Expected: no output (every file already gofmt-clean).

Run: `./tool/go build ./...`
Expected: success.

- [ ] **Step 3: Manual smoke (only if a local tailscaled-dev is handy)**

Skip if no dev daemon. Otherwise:

```bash
# Bring up a join (assume devcontrol running with a blueprint defined)
./tool/go run ./cmd/tailscale join --login-server=http://localhost:31544 \
    --blueprint=bp:test-bp --auth-key=$OAUTH_SECRET

# Then:
./tool/go run ./cmd/tailscale join status
./tool/go run ./cmd/tailscale join status --json | jq .

# Then tear down:
./tool/go run ./cmd/tailscale leave
```

Expected behavior:
- `join` prints "Bound to blueprint bp:test-bp." followed by the projection block (or, after 30s, "Projection not yet received; run 'tailscale join status' to see it.").
- `join status` prints the projection + peer section.
- `join status --json` parses cleanly with `jq`.
- `leave` prints "Detached from blueprint bp:test-bp. Released:" followed by the projection.

- [ ] **Step 4: No commit needed; this task is verification only.**

---

## Spec coverage check

| Spec requirement | Task |
|---|---|
| `join` waits and renders projection (Section 2) | Task 4 + Task 5 |
| `leave` renders projection pre-logout (Section 2) | Task 7 |
| `join status` subcommand (Section 2) | Task 6 |
| `--json` on `join status` only (Section 2) | Task 6 |
| `PeerStatus.BlueprintID` plumbing (Section 3) | Task 1 |
| Population from `Node.BlueprintID` (Section 3) | Task 2 |
| Self projection on `Status.Self.BlueprintConfig` (Section 3) | Task 4 (added to PeerStatus + plumbed in peerStatusFromNode) |
| Output format (Section 4) | Task 3 + Task 6 |
| Edge cases: not-bound, projection-nil, timeout, stale-id (Section 5) | Task 4 (helper) + Task 6 (renderer) + Task 5 (timeout msg) + Task 7 (fallback) |
| New telemetry counter (Section 5) | Task 5 |
| Tests: renderer, wait helper, subcommand, leave, AddPeer merge, peerStatusFromNode (Section 6) | Tasks 1-7 each include their tests |
