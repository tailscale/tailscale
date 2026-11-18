// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package linuxdnsfight

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

// startWatch runs watchFile on dir/filename and returns a channel that
// receives a value for each callback. It waits for the callback that
// watchFile makes at startup, so the watch is in place on return.
func startWatch(t *testing.T, dir, filename string) <-chan struct{} {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan struct{}, 100)
	var eg errgroup.Group
	eg.Go(func() error {
		return watchFile(ctx, dir, filename, func() { calls <- struct{}{} })
	})
	t.Cleanup(func() {
		cancel()
		if err := eg.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	select {
	case <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("no callback at startup")
	}
	return calls
}

func TestWatchFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	calls := startWatch(t, dir, path)

	if err := os.WriteFile(path, []byte("write"), 0644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("callback was not called after write")
	}
}

func TestWatchFileIgnoresReadsAndOtherFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	calls := startWatch(t, dir, path)

	for range 100 {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-calls:
		t.Fatal("callback called for reads or another file")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestWatchFileLongName checks that the read buffer holds an event for a
// file with the longest name Linux allows, and that watching continues.
func TestWatchFileLongName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	calls := startWatch(t, dir, path)

	long := filepath.Join(dir, strings.Repeat("x", unix.NAME_MAX))
	for range 3 {
		if err := os.WriteFile(long, nil, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(long); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("callback was not called after long-name events and a write")
	}
}

// inotifyWatches returns the number of inotify fds held by this process
// and the masks of their watches, read from /proc/self/fdinfo.
func inotifyWatches(t *testing.T) (fds int, masks []uint64) {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		target, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil || target != "anon_inode:inotify" {
			continue
		}
		fds++
		info, err := os.ReadFile("/proc/self/fdinfo/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.Lines(string(info)) {
			if !strings.HasPrefix(line, "inotify ") {
				continue
			}
			for f := range strings.FieldsSeq(line) {
				if hex, ok := strings.CutPrefix(f, "mask:"); ok {
					m, err := strconv.ParseUint(hex, 16, 32)
					if err != nil {
						t.Fatalf("bad fdinfo line %q: %v", line, err)
					}
					masks = append(masks, m)
				}
			}
		}
	}
	return fds, masks
}

func TestWatchFileKernelMask(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- watchFile(ctx, dir, filepath.Join(dir, "resolv.conf"), func() {
			select {
			case started <- struct{}{}:
			default:
			}
		})
	}()
	<-started

	fds, masks := inotifyWatches(t)
	if fds != 1 || len(masks) != 1 {
		t.Fatalf("got %d inotify fds with %d watches; want 1 fd with 1 watch", fds, len(masks))
	}
	const readEvents = unix.IN_OPEN | unix.IN_ACCESS | unix.IN_CLOSE_NOWRITE
	if masks[0]&readEvents != 0 {
		t.Errorf("watch mask %#x includes read events", masks[0])
	}

	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Errorf("watchFile = %v; want context.Canceled", err)
	}
	if fds, _ := inotifyWatches(t); fds != 0 {
		t.Errorf("%d inotify fds still open after watchFile returned", fds)
	}
}

func TestWatchFileDirRemoved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		errc <- watchFile(t.Context(), dir, filepath.Join(dir, "resolv.conf"), func() {
			close(started)
		})
	}()
	<-started
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, errWatchRemoved) {
			t.Errorf("watchFile = %v; want errWatchRemoved", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watchFile did not return after its directory was removed")
	}
}

// event encodes one inotify_event record, padding the name the way the
// kernel does.
func event(wd int32, mask uint32, name string) []byte {
	nameLen := 0
	if name != "" {
		nameLen = (len(name) + unix.SizeofInotifyEvent) &^ (unix.SizeofInotifyEvent - 1)
	}
	b := make([]byte, unix.SizeofInotifyEvent+nameLen)
	binary.NativeEndian.PutUint32(b[0:], uint32(wd))
	binary.NativeEndian.PutUint32(b[4:], mask)
	binary.NativeEndian.PutUint32(b[12:], uint32(nameLen))
	copy(b[unix.SizeofInotifyEvent:], name)
	return b
}

// badLen returns an inotify_event header whose name length is nameLen,
// with no name bytes after it.
func badLen(nameLen uint32) []byte {
	return binary.NativeEndian.AppendUint32(make([]byte, 12), nameLen)
}

func TestParseEvents(t *testing.T) {
	cat := func(bs ...[]byte) []byte { return bytes.Join(bs, nil) }
	tests := []struct {
		name        string
		buf         []byte
		wantChanged bool
		wantErr     string // substring; empty means no error
	}{
		{name: "empty"},
		{name: "match", buf: event(1, unix.IN_CLOSE_WRITE, "resolv.conf"), wantChanged: true},
		{name: "other-file", buf: event(1, unix.IN_CLOSE_WRITE, "hostname")},
		{name: "longer-name", buf: event(1, unix.IN_CREATE, "resolv.conf.tmp")},
		{name: "16-byte-name", buf: event(1, unix.IN_CREATE, "resolv.conf.abcd")},
		{
			name: "match-after-others",
			buf: cat(
				event(1, unix.IN_CREATE, "resolv.conf.tmp"),
				event(1, unix.IN_MOVED_FROM, "resolv.conf.tmp"),
				event(1, unix.IN_MOVED_TO, "resolv.conf"),
			),
			wantChanged: true,
		},
		{name: "overflow", buf: event(-1, unix.IN_Q_OVERFLOW, ""), wantChanged: true},
		{name: "watch-removed", buf: event(1, unix.IN_IGNORED, ""), wantErr: "watch removed"},
		{name: "short-header", buf: event(1, unix.IN_CREATE, "resolv.conf")[:10], wantErr: "10 trailing bytes"},
		{name: "trailing-bytes", buf: cat(event(1, unix.IN_CREATE, "a"), []byte{1, 2, 3}), wantErr: "3 trailing bytes"},
		{
			// gonotify v3.0.2 looped forever on a record like this,
			// whose name runs past the end of the read (#16576).
			// 761623152 is "pre-", as seen in #14699.
			name:    "name-past-end",
			buf:     badLen(761623152),
			wantErr: "name length 761623152",
		},
		{
			name:    "max-name-len-after-valid",
			buf:     cat(event(1, unix.IN_CREATE, "resolv.conf"), badLen(0xffffffff)),
			wantErr: "name length 4294967295",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed, err := parseEvents(tt.buf, "resolv.conf")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v; want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if changed != tt.wantChanged {
				t.Errorf("changed = %v; want %v", changed, tt.wantChanged)
			}
		})
	}
}
