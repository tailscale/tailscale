// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

// Package linuxdnsfight provides Linux support for detecting DNS fights
// (inotify watching of /etc/resolv.conf).
package linuxdnsfight

import (
	"context"
	"fmt"

	"github.com/illarion/gonotify/v3"
	"tailscale.com/net/dns"
)

func init() {
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

	watcher, err := gonotify.NewDirWatcher(ctx, events, dir)
	if err != nil {
		return fmt.Errorf("NewDirWatcher: %w", err)
	}

	for {
		select {
		case event := <-watcher.C:
			if event.Name == filename {
				cb()
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
