// Copyright (c) Tailscale Inc & AUTHORS
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

	if os.Getuid() != 0 {
		t.Skip("test only works when run as root")
	}

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

	var u1 user.UnknownUserIdError
	if errors.As(err, &u1) {
		return false
	}
	var u2 user.UnknownUserError
	if errors.As(err, &u2) {
		return false
	}

	// Some other error; might be valid
	return true
}

func maybeValidGID(id int) bool {
	_, err := user.LookupGroupId(strconv.Itoa(id))
	if err == nil {
		return true
	}

	var u1 user.UnknownGroupIdError
	if errors.As(err, &u1) {
		return false
	}
	var u2 user.UnknownGroupError
	if errors.As(err, &u2) {
		return false
	}

	// Some other error; might be valid
	return true
}
