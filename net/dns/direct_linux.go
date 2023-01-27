// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"context"

	"github.com/illarion/gonotify"
)

func (m *directManager) runFileWatcher() {
	in, err := gonotify.NewInotify()
	if err != nil {
		// Oh well, we tried. This is all best effort for now, to
		// surface warnings to users.
		m.logf("dns: inotify new: %v", err)
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	defer cancel()
	go m.closeInotifyOnDone(ctx, in)

	const events = gonotify.IN_ATTRIB |
		gonotify.IN_CLOSE_WRITE |
		gonotify.IN_CREATE |
		gonotify.IN_DELETE |
		gonotify.IN_MODIFY |
		gonotify.IN_MOVE

	if err := in.AddWatch("/etc/", events); err != nil {
		m.logf("dns: inotify addwatch: %v", err)
		return
	}
	for {
		events, err := in.Read()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			m.logf("dns: inotify read: %v", err)
			return
		}
		var match bool
		for _, ev := range events {
			if ev.Name == resolvConf {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		m.checkForFileTrample()
	}
}

func (m *directManager) closeInotifyOnDone(ctx context.Context, in *gonotify.Inotify) {
	<-ctx.Done()
	in.Close()
}
