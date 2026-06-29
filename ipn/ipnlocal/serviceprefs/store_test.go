// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package serviceprefs

import (
	"encoding/hex"
	jsonv1 "encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/ipn"
)

var (
	timeIn2026 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	timeIn1970 = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
)

var cmpOpts = []cmp.Option{cmpopts.EquateApproxTime(0), cmpopts.EquateEmpty()}

func TestInMemoryStoreCleanup(t *testing.T) {
	pid := ipn.ProfileID("pid")
	type input struct {
		key  string
		pref ipn.ServicePref
	}
	tests := []struct {
		name      string
		retention time.Duration
		inputs    []input
		want      ipn.ServicePrefs
	}{
		{
			name:      "expired pref cleaned up immediately",
			retention: 24 * time.Hour,
			inputs:    []input{{"old", makePref("this-client", timeIn2026.Add(-48*time.Hour))}},
			want:      ipn.ServicePrefs{},
		},
		{
			name:      "retention disabled keeps ancient entry",
			retention: 0,
			inputs:    []input{{"old", makePref("this-client", timeIn1970)}},
			want:      ipn.ServicePrefs{"old": makePref("this-client", timeIn1970)},
		},
		{
			name:      "multiple fresh entries kept",
			retention: 24 * time.Hour,
			inputs: []input{
				{"this", makePref("this-client", timeIn2026)},
				{"that", makePref("that-client", timeIn2026)},
			},
			want: ipn.ServicePrefs{
				"this": makePref("this-client", timeIn2026),
				"that": makePref("that-client", timeIn2026),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			store := NewInMemoryStore(tt.retention, func() time.Time { return timeIn2026 })
			for _, in := range tt.inputs {
				if err := store.SaveForService(ctx, pid, in.key, in.pref); err != nil {
					t.Fatal(err)
				}
			}
			got, err := store.LoadForProfile(ctx, pid)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got, cmpOpts...); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func TestInMemoryStoreCleanupOnLaterSave(t *testing.T) {
	ctx := t.Context()
	pid := ipn.ProfileID("pid")

	store := NewInMemoryStore(24*time.Hour, func() time.Time { return timeIn2026 })
	if err := store.SaveForService(ctx, pid, "old", makePref("this-client", timeIn2026)); err != nil {
		t.Fatal(err)
	}

	twoDaysLater := timeIn2026.Add(48 * time.Hour)

	store.now = func() time.Time { return twoDaysLater }
	if err := store.SaveForService(ctx, pid, "new", makePref("that-client", twoDaysLater)); err != nil {
		t.Fatal(err)
	}

	got, err := store.LoadForProfile(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	want := ipn.ServicePrefs{"new": makePref("that-client", twoDaysLater)}
	if diff := cmp.Diff(want, got, cmpOpts...); diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
}

func TestInMemoryStoreSaveLoadDelete(t *testing.T) {
	ctx := t.Context()
	store := NewInMemoryStore(0, time.Now)
	pid1 := ipn.ProfileID("pid1")
	pid2 := ipn.ProfileID("pid2")

	got, err := store.LoadForProfile(ctx, pid1)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("unknown profile: want empty non-nil map, got %#v", got)
	}

	if err := store.SaveForService(ctx, pid1, "ssh:22", makePref("terminal", timeIn2026)); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveForService(ctx, pid2, "db:5432", makePref("psql", timeIn2026)); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteForProfile(ctx, pid1); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.LoadForProfile(ctx, pid1); len(got) != 0 {
		t.Errorf("pid1 not deleted: %v", got)
	}
	if got, _ := store.LoadForProfile(ctx, pid2); len(got) != 1 {
		t.Errorf("pid2 unexpectedly affected: %v", got)
	}
}

func TestInMemoryStoreLoadReturnsClone(t *testing.T) {
	ctx := t.Context()
	store := NewInMemoryStore(0, time.Now)
	pid := ipn.ProfileID("pid")
	if err := store.SaveForService(ctx, pid, "k", makePref("a", timeIn2026)); err != nil {
		t.Fatal(err)
	}

	got, _ := store.LoadForProfile(ctx, pid)
	got["k"] = makePref("MUTATED", timeIn2026)
	got["injected"] = makePref("x", timeIn2026)

	again, _ := store.LoadForProfile(ctx, pid)
	want := ipn.ServicePrefs{"k": makePref("a", timeIn2026)}
	if diff := cmp.Diff(want, again, cmpOpts...); diff != "" {
		t.Errorf("store mutated through returned map (-want +got):\n%s", diff)
	}
}

func TestFileStorePersistsAcrossReopen(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	pid := ipn.ProfileID("pid")

	store, err := NewFileStore(ctx, dir, 0, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	want := ipn.ServicePrefs{
		"ssh:22":  makePref("terminal", timeIn2026),
		"db:5432": {Client: "psql", Username: "rollie", DatabaseName: "prod", LastUsed: timeIn2026},
	}
	for k, v := range want {
		if err := store.SaveForService(ctx, pid, k, v); err != nil {
			t.Fatal(err)
		}
	}

	store2, err := NewFileStore(ctx, dir, 0, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store2.LoadForProfile(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got, cmpOpts...); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestFileStorePerProfileIsolation(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	store, err := NewFileStore(ctx, dir, 0, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	pidA := ipn.ProfileID("pidA")
	pidB := ipn.ProfileID("pidB")
	if err := store.SaveForService(ctx, pidA, "ssh:22", makePref("a", timeIn2026)); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveForService(ctx, pidB, "ssh:22", makePref("b", timeIn2026)); err != nil {
		t.Fatal(err)
	}

	if !profileFileExists(t, dir, pidA) || !profileFileExists(t, dir, pidB) {
		t.Fatal("expected a separate file per profile")
	}

	if err := store.DeleteForProfile(ctx, pidA); err != nil {
		t.Fatal(err)
	}
	if profileFileExists(t, dir, pidA) {
		t.Error("profile A file was not removed on delete")
	}
	if got, _ := store.LoadForProfile(ctx, pidB); len(got) != 1 {
		t.Errorf("profile B affected by deleting A: %v", got)
	}
}

func TestFileStoreExpiredSaveRemovesFile(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	store, err := NewFileStore(ctx, dir, 24*time.Hour, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	pid := ipn.ProfileID("pid")

	if err := store.SaveForService(ctx, pid, "old", makePref("a", timeIn1970)); err != nil {
		t.Fatal(err)
	}
	if profileFileExists(t, dir, pid) {
		t.Error("expected no file for an emptied profile")
	}
	if got, _ := store.LoadForProfile(ctx, pid); len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestFileStoreCleanupOnLoad(t *testing.T) {
	pid := ipn.ProfileID("pid")
	fresh := makePref("fresh", time.Now().UTC().Add(-time.Minute).Truncate(time.Second))
	tests := []struct {
		name     string
		seed     ipn.ServicePrefs
		want     ipn.ServicePrefs
		wantFile bool
	}{
		{
			name:     "all expired removes orphan file",
			seed:     ipn.ServicePrefs{"ssh:22": makePref("terminal", timeIn1970)},
			want:     ipn.ServicePrefs{},
			wantFile: false,
		},
		{
			name:     "fresh entry kept and file retained",
			seed:     ipn.ServicePrefs{"old": makePref("old", timeIn1970), "new": fresh},
			want:     ipn.ServicePrefs{"new": fresh},
			wantFile: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			dir := t.TempDir()
			seedProfileFile(t, dir, pid, tt.seed)

			store, err := NewFileStore(ctx, dir, 24*time.Hour, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			got, err := store.LoadForProfile(ctx, pid)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got, cmpOpts...); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
			if gotFile := profileFileExists(t, dir, pid); gotFile != tt.wantFile {
				t.Errorf("file exists = %v, want %v", gotFile, tt.wantFile)
			}
		})
	}
}

func TestFileStoreConcurrentSaveDelete(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	store, err := NewFileStore(ctx, dir, 0, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	pid := ipn.ProfileID("pid")

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%4 == 0 {
				_ = store.DeleteForProfile(ctx, pid)
			} else {
				_ = store.SaveForService(ctx, pid, fmt.Sprintf("svc:%d", i), makePref("c", timeIn2026))
			}
		}(i)
	}
	wg.Wait()

	mem, err := store.LoadForProfile(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	disk := readDiskForProfile(t, dir, pid)
	if diff := cmp.Diff(mem, disk, cmpOpts...); diff != "" {
		t.Errorf("disk != memory after concurrent ops (-mem +disk):\n%s", diff)
	}
}

func makePref(client string, lastUsed time.Time) ipn.ServicePref {
	return ipn.ServicePref{Client: client, LastUsed: lastUsed}
}

func profilePath(dir string, pid ipn.ProfileID) string {
	return filepath.Join(dir, hex.EncodeToString([]byte(pid))+".json")
}

func profileFileExists(t *testing.T, dir string, pid ipn.ProfileID) bool {
	t.Helper()
	_, err := os.Stat(profilePath(dir, pid))
	switch {
	case err == nil:
		return true
	case errors.Is(err, os.ErrNotExist):
		return false
	default:
		t.Fatal(err)
		return false
	}
}

func seedProfileFile(t *testing.T, dir string, pid ipn.ProfileID, prefs ipn.ServicePrefs) {
	t.Helper()
	data, err := jsonv1.Marshal(prefs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath(dir, pid), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func readDiskForProfile(t *testing.T, dir string, pid ipn.ProfileID) ipn.ServicePrefs {
	t.Helper()
	data, err := os.ReadFile(profilePath(dir, pid))
	if errors.Is(err, os.ErrNotExist) {
		return ipn.ServicePrefs{}
	}
	if err != nil {
		t.Fatal(err)
	}
	var prefs ipn.ServicePrefs
	if err := jsonv1.Unmarshal(data, &prefs); err != nil {
		t.Fatal(err)
	}
	return prefs
}
