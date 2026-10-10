// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

// Package linuxdnsfight provides Linux support for detecting DNS fights
// (inotify watching of /etc/resolv.conf).
package linuxdnsfight

import (
	"context"
	"fmt"

	"github.com/illarion/gonotify/v3"
	"tailscale.com/feature"
	"tailscale.com/net/dns"
)

func init() {
	if !feature.Register("linuxdnsfight") {
		return
	}
	dns.HookWatchFile.Set(watchFile)
}

// watchFile sets up an inotify watch for a given directory and
// calls the callback function every time a particular file is changed.
// The filename should be located in the provided directory.
func watchFile(ctx context.Context, dir, filename string, cb func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	const events = gonotify.IN_ATTRIB |
		gonotify.IN_CLOSE_WRITE |
		gonotify.IN_CREATE |
		gonotify.IN_DELETE |
		gonotify.IN_MODIFY |
		gonotify.IN_MOVE

	// Watch only dir itself (not recursively) and only for the events
	// above. gonotify.NewDirWatcher registers IN_ALL_EVENTS on every
	// subdirectory and filters afterwards, so every open or read under
	// /etc (including /etc/ld.so.cache on each exec) woke this goroutine.
	in, err := gonotify.NewInotify(ctx)
	if err != nil {
		return fmt.Errorf("NewInotify: %w", err)
	}
	if _, err := in.AddWatch(dir, events|gonotify.IN_ONLYDIR); err != nil {
		return fmt.Errorf("AddWatch: %w", err)
	}

	// NewDirWatcher used to emit a synthetic event for existing files,
	// which ran cb once at startup. Keep that behavior.
	cb()

	for {
		evs, err := in.Read()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("Read: %w", err)
		}
		for _, ev := range evs {
			if ev.Name == filename {
				cb()
				break
			}
		}
	}
}
