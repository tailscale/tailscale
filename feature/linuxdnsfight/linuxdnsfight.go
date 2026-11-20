// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

// Package linuxdnsfight provides Linux support for detecting DNS fights
// (inotify watching of /etc/resolv.conf).
package linuxdnsfight

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"tailscale.com/feature"
	"tailscale.com/net/dns"
)

func init() {
	if !feature.Register("linuxdnsfight") {
		return
	}
	dns.HookWatchFile.Set(watchFile)
}

// watchEvents are the inotify events that indicate a file in the watched
// directory may have changed.
const watchEvents = unix.IN_ATTRIB |
	unix.IN_CLOSE_WRITE |
	unix.IN_CREATE |
	unix.IN_DELETE |
	unix.IN_MODIFY |
	unix.IN_MOVE

// watchFile sets up an inotify watch for a given directory and
// calls the callback function every time a particular file is changed.
// The filename should be located in the provided directory.
//
// It calls cb once after the watch is in place, so changes made before
// watchFile was called are not missed.
func watchFile(ctx context.Context, dir, filename string, cb func()) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}
	// The fd is non-blocking, so os.NewFile registers it with the runtime
	// poller. Reads then block without a thread, and Close from another
	// goroutine unblocks them.
	f := os.NewFile(uintptr(fd), "inotify")
	defer f.Close()

	// Watch only dir itself (not recursively) and only for watchEvents, so
	// the kernel drops opens and reads of other files in dir.
	if _, err := unix.InotifyAddWatch(fd, dir, watchEvents|unix.IN_ONLYDIR); err != nil {
		return fmt.Errorf("inotify_add_watch %q: %w", dir, err)
	}

	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()

	cb()

	base := filepath.Base(filename)
	// The kernel only returns whole records and fails the read with EINVAL
	// if the next one doesn't fit, so size buf for one record with the
	// longest possible name. Events are rare, so reading one or a few per
	// read is fine.
	var buf [unix.SizeofInotifyEvent + unix.NAME_MAX + 1]byte
	for {
		n, err := f.Read(buf[:])
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("inotify read: %w", err)
		}
		changed, err := parseEvents(buf[:n], base)
		if err != nil {
			return err
		}
		if changed {
			cb()
		}
	}
}

// errWatchRemoved is returned by [parseEvents] when the kernel removed the
// watch, such as when the watched directory was deleted or unmounted.
var errWatchRemoved = errors.New("inotify watch removed")

// parseEvents parses the inotify_event records in buf, as returned by one
// read of an inotify fd. It reports whether any of them may indicate a
// change to the file named base, or that events were lost.
//
// It returns an error if buf is malformed. The kernel only returns whole
// records, so a malformed buf means something other than the kernel's
// inotify code produced it.
func parseEvents(buf []byte, base string) (changed bool, err error) {
	for len(buf) > 0 {
		if len(buf) < unix.SizeofInotifyEvent {
			return false, fmt.Errorf("malformed inotify read: %d trailing bytes", len(buf))
		}
		mask := binary.NativeEndian.Uint32(buf[4:])
		nameLen := binary.NativeEndian.Uint32(buf[12:])
		if uint64(nameLen) > uint64(len(buf)-unix.SizeofInotifyEvent) {
			return false, fmt.Errorf("malformed inotify read: name length %d exceeds remaining %d bytes", nameLen, len(buf)-unix.SizeofInotifyEvent)
		}
		name := buf[unix.SizeofInotifyEvent:][:nameLen]
		buf = buf[unix.SizeofInotifyEvent+int(nameLen):]

		if mask&unix.IN_IGNORED != 0 {
			return false, errWatchRemoved
		}
		if mask&unix.IN_Q_OVERFLOW != 0 {
			changed = true
			continue
		}
		if i := bytes.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		if string(name) == base {
			changed = true
		}
	}
	return changed, nil
}
