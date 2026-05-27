// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package tailssh

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"syscall"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/types/logger"
)

func TestDoDropPrivileges(t *testing.T) {
	type SubprocInput struct {
		UID              int
		GID              int
		AdditionalGroups []int
	}
	type SubprocOutput struct {
		UID              int
		GID              int
		EUID             int
		EGID             int
		AdditionalGroups []int
	}

	if v := os.Getenv("TS_TEST_DROP_PRIVILEGES_CHILD"); v != "" {
		t.Logf("in child process")

		var input SubprocInput
		if err := json.Unmarshal([]byte(v), &input); err != nil {
			t.Fatal(err)
		}

		// Get a handle to our provided JSON file before dropping privs.
		f := os.NewFile(3, "out.json")

		// We're in our subprocess; actually drop privileges now.
		doDropPrivileges(t.Logf, input.UID, input.GID, input.AdditionalGroups, "/")

		additional, _ := syscall.Getgroups()

		// Print our IDs
		json.NewEncoder(f).Encode(SubprocOutput{
			UID:              os.Getuid(),
			GID:              os.Getgid(),
			EUID:             os.Geteuid(),
			EGID:             os.Getegid(),
			AdditionalGroups: additional,
		})

		// Close output file to ensure that it's flushed to disk before we exit
		f.Close()

		// Always exit the process now that we have a different
		// UID/GID/etc.; we don't want the Go test framework to try and
		// clean anything up, since it might no longer have access.
		os.Exit(0)
	}

	tstest.RequireRoot(t)

	rerunSelf := func(t *testing.T, input SubprocInput) []byte {
		fpath := filepath.Join(t.TempDir(), "out.json")
		outf, err := os.Create(fpath)
		if err != nil {
			t.Fatal(err)
		}

		inputb, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(os.Args[0], "-test.v", "-test.run", "^"+regexp.QuoteMeta(t.Name())+"$")
		cmd.Env = append(os.Environ(), "TS_TEST_DROP_PRIVILEGES_CHILD="+string(inputb))
		cmd.ExtraFiles = []*os.File{outf}
		cmd.Stdout = logger.FuncWriter(logger.WithPrefix(t.Logf, "child: "))
		cmd.Stderr = logger.FuncWriter(logger.WithPrefix(t.Logf, "child: "))
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		outf.Close()

		jj, err := os.ReadFile(fpath)
		if err != nil {
			t.Fatal(err)
		}
		return jj
	}

	// We want to ensure we're not colliding with existing users; find some
	// unused UIDs and GIDs for the tests we run.
	uid1 := findUnusedUID(t)
	gid1 := findUnusedGID(t)
	gid2 := findUnusedGID(t, gid1)
	gid3 := findUnusedGID(t, gid1, gid2)

	// For some tests, we want a UID/GID pair with the same numerical
	// value; this finds one.
	uidgid1 := findUnusedUIDGID(t, uid1, gid1, gid2, gid3)

	t.Logf("uid1=%d gid1=%d gid2=%d gid3=%d uidgid1=%d",
		uid1, gid1, gid2, gid3, uidgid1)

	testCases := []struct {
		name             string
		uid              int
		gid              int
		additionalGroups []int
	}{
		{
			name:             "all_different_values",
			uid:              uid1,
			gid:              gid1,
			additionalGroups: []int{gid2, gid3},
		},
		{
			name:             "no_additional_groups",
			uid:              uid1,
			gid:              gid1,
			additionalGroups: []int{},
		},
		// This is a regression test for the following bug, triggered
		// on Darwin & FreeBSD:
		//    https://github.com/tailscale/tailscale/issues/7616
		{
			name:             "same_values",
			uid:              uidgid1,
			gid:              uidgid1,
			additionalGroups: []int{uidgid1},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			subprocOut := rerunSelf(t, SubprocInput{
				UID:              tt.uid,
				GID:              tt.gid,
				AdditionalGroups: tt.additionalGroups,
			})

			var out SubprocOutput
			if err := json.Unmarshal(subprocOut, &out); err != nil {
				t.Logf("%s", subprocOut)
				t.Fatal(err)
			}
			t.Logf("output: %+v", out)

			if out.UID != tt.uid {
				t.Errorf("got uid %d; want %d", out.UID, tt.uid)
			}
			if out.GID != tt.gid {
				t.Errorf("got gid %d; want %d", out.GID, tt.gid)
			}
			if out.EUID != tt.uid {
				t.Errorf("got euid %d; want %d", out.EUID, tt.uid)
			}
			if out.EGID != tt.gid {
				t.Errorf("got egid %d; want %d", out.EGID, tt.gid)
			}

			// On FreeBSD and Darwin, the set of additional groups
			// is prefixed with the egid; handle that case by
			// modifying our expected set.
			wantGroups := make(map[int]bool)
			for _, id := range tt.additionalGroups {
				wantGroups[id] = true
			}
			if runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" {
				wantGroups[tt.gid] = true
			}

			gotGroups := make(map[int]bool)
			for _, id := range out.AdditionalGroups {
				gotGroups[id] = true
			}

			if !reflect.DeepEqual(gotGroups, wantGroups) {
				t.Errorf("got additional groups %+v; want %+v", gotGroups, wantGroups)
			}
		})
	}
}

func findUnusedUID(t *testing.T, not ...int) int {
	for i := 1000; i < 65535; i++ {
		// Skip UIDs that might be valid
		if maybeValidUID(i) {
			continue
		}

		// Skip UIDs that we're avoiding
		if slices.Contains(not, i) {
			continue
		}

		// Not a valid UID, not one we're avoiding... all good!
		return i
	}

	t.Fatalf("unable to find an unused UID")
	return -1
}

func findUnusedGID(t *testing.T, not ...int) int {
	for i := 1000; i < 65535; i++ {
		if maybeValidGID(i) {
			continue
		}

		// Skip GIDs that we're avoiding
		if slices.Contains(not, i) {
			continue
		}

		// Not a valid GID, not one we're avoiding... all good!
		return i
	}

	t.Fatalf("unable to find an unused GID")
	return -1
}

func findUnusedUIDGID(t *testing.T, not ...int) int {
	for i := 1000; i < 65535; i++ {
		if maybeValidUID(i) || maybeValidGID(i) {
			continue
		}

		// Skip IDs that we're avoiding
		if slices.Contains(not, i) {
			continue
		}

		// Not a valid ID, not one we're avoiding... all good!
		return i
	}

	t.Fatalf("unable to find an unused UID/GID pair")
	return -1
}

func maybeValidUID(id int) bool {
	_, err := user.LookupId(strconv.Itoa(id))
	if err == nil {
		return true
	}

	if _, ok := errors.AsType[user.UnknownUserIdError](err); ok {
		return false
	}
	if _, ok := errors.AsType[user.UnknownUserError](err); ok {
		return false
	}

	// Some other error; might be valid
	return true
}

// TestSetGroupsSkipsSyscallWhenEffectivelyEqual verifies that setGroups
// short-circuits without invoking syscall.Setgroups when the requested
// groups would leave the process's effective access rights unchanged. This
// matters in sandboxed environments (rootless containers, gVisor, etc.)
// where the process lacks CAP_SETGID and the syscall would fail with
// EPERM even when the call is a semantic no-op. The test is intentionally
// non-root-only so we have non-privileged coverage of the fast path.
//
// Two skip cases are exercised:
//
//   - the requested supplementary set equals the current one (the case the
//     #6888 EPERM-recovery already covered, now lifted to a pre-check).
//   - the requested set restates the primary GID and contains no other
//     entry, while the current supplementary set is empty — the typical
//     shape we hit when tailscaled runs as the target user but the user
//     has no real secondary group memberships (the box+gVisor case).
func TestSetGroupsSkipsSyscallWhenEffectivelyEqual(t *testing.T) {
	current, err := syscall.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups: %v", err)
	}

	// Case 1: identical set (reversed, to also pin set-equality semantics).
	reversed := slices.Clone(current)
	slices.Reverse(reversed)
	if err := setGroups(reversed); err != nil {
		t.Fatalf("setGroups(identical current) returned error: %v", err)
	}

	// Case 2: target equals only the primary GID. This is a no-op when the
	// current supplementary set is empty, because the primary GID already
	// grants the same access. We only exercise it when getgroups() is
	// empty; if the test environment has supplementary groups we'd be
	// expanding access by skipping, which must NOT happen.
	if len(current) == 0 {
		egid := os.Getegid()
		if err := setGroups([]int{egid}); err != nil {
			t.Fatalf("setGroups([egid]) returned error: %v", err)
		}
	}

	after, err := syscall.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups: %v", err)
	}
	wantSet := make(map[int]struct{}, len(current))
	for _, g := range current {
		wantSet[g] = struct{}{}
	}
	gotSet := make(map[int]struct{}, len(after))
	for _, g := range after {
		gotSet[g] = struct{}{}
	}
	if !reflect.DeepEqual(wantSet, gotSet) {
		t.Errorf("supplementary groups changed unexpectedly: before=%v after=%v",
			current, after)
	}
}

// TestEffectiveGroupsEqual pins the helper's semantics: it must return
// true exactly when skipping syscall.Setgroups would leave the
// (primary GID ∪ supplementary) effective set unchanged. False negatives
// are merely a missed optimisation; false positives are a correctness
// hazard (skipping a real privilege drop), so the test is careful to
// exercise both sides of that line.
func TestEffectiveGroupsEqual(t *testing.T) {
	current, err := syscall.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups: %v", err)
	}
	egid := os.Getegid()

	// Identical supplementary sets (any order) must match.
	if !effectiveGroupsEqual(current) {
		t.Errorf("effectiveGroupsEqual(%v) = false; want true (identical)", current)
	}
	reversed := slices.Clone(current)
	slices.Reverse(reversed)
	if !effectiveGroupsEqual(reversed) {
		t.Errorf("effectiveGroupsEqual(%v) = false; want true (reordered)", reversed)
	}

	// The primary GID is implicitly part of the effective set. Asking for
	// it as a supplementary group when no other supplementary groups exist
	// must be treated as effectively equal to the current state.
	if len(current) == 0 {
		if !effectiveGroupsEqual([]int{egid}) {
			t.Errorf("effectiveGroupsEqual([egid]) = false; want true (egid covers it)")
		}
	}

	// A request that adds a group not currently held (and not the primary
	// GID) must not be treated as effectively equal: skipping would leave
	// access strictly narrower than the caller asked for.
	other := 0xDEAD
	for _, g := range current {
		if g == other {
			other++
		}
	}
	if other == egid {
		other++
	}
	if effectiveGroupsEqual(append(slices.Clone(current), other)) {
		t.Errorf("effectiveGroupsEqual(current+other) = true; want false (extra group)")
	}

	// Conversely, a request that drops a real supplementary group (one
	// that is not the primary GID) must not be treated as effectively
	// equal: skipping would leave access strictly wider than the caller
	// asked for, which would defeat the privilege drop.
	var realSupp int
	hasRealSupp := false
	for _, g := range current {
		if g != egid {
			realSupp = g
			hasRealSupp = true
			break
		}
	}
	if hasRealSupp {
		without := make([]int, 0, len(current)-1)
		for _, g := range current {
			if g != realSupp {
				without = append(without, g)
			}
		}
		if effectiveGroupsEqual(without) {
			t.Errorf("effectiveGroupsEqual(current without %d) = true; want false (dropping a real group)",
				realSupp)
		}
	}
}

// TestGroupsMatchCurrent keeps explicit coverage of the strict
// set-equality helper that the EPERM-recovery fallback still relies on.
func TestGroupsMatchCurrent(t *testing.T) {
	current, err := syscall.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups: %v", err)
	}

	if !groupsMatchCurrent(current) {
		t.Errorf("groupsMatchCurrent(%v) = false, want true (identical slice)", current)
	}

	reversed := slices.Clone(current)
	slices.Reverse(reversed)
	if !groupsMatchCurrent(reversed) {
		t.Errorf("groupsMatchCurrent(%v) = false; ordering should not matter", reversed)
	}

	if got := groupsMatchCurrent(nil); got != (len(current) == 0) {
		t.Errorf("groupsMatchCurrent(nil) = %v; want %v", got, len(current) == 0)
	}

	extra := append(slices.Clone(current), 0xDEAD)
	if groupsMatchCurrent(extra) {
		t.Errorf("groupsMatchCurrent(%v) = true; want false (extra entry)", extra)
	}
}

func maybeValidGID(id int) bool {
	_, err := user.LookupGroupId(strconv.Itoa(id))
	if err == nil {
		return true
	}

	if _, ok := errors.AsType[user.UnknownGroupIdError](err); ok {
		return false
	}
	if _, ok := errors.AsType[user.UnknownGroupError](err); ok {
		return false
	}

	// Some other error; might be valid
	return true
}
