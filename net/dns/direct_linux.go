// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package dns

import (
	"bytes"
	"context"
	"fmt"

	"github.com/illarion/gonotify/v3"
	"tailscale.com/health"
)

func (m *directManager) runFileWatcher() {
	if err := watchFile(m.ctx, "/etc/", resolvConf, m.checkForFileTrample); err != nil {
		// This is all best effort for now, so surface warnings to users.
		m.logf("dns: inotify: %s", err)
	}
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

var resolvTrampleWarnable = health.Register(&health.Warnable{
	Code:     "resolv-conf-overwritten",
	Severity: health.SeverityMedium,
	Title:    "Linux DNS configuration issue",
	Text:     health.StaticMessage("Linux DNS config not ideal. /etc/resolv.conf overwritten. See https://tailscale.com/s/dns-fight"),
})

// checkForFileTrample checks whether /etc/resolv.conf has been trampled
// by another program on the system. (e.g. a DHCP client)
func (m *directManager) checkForFileTrample() {
	m.mu.Lock()
	want := m.wantResolvConf
	lastWarn := m.lastWarnContents
	m.mu.Unlock()

	if want == nil {
		return
	}

	cur, err := m.fs.ReadFile(resolvConf)
	if err != nil {
		m.logf("trample: read error: %v", err)
		return
	}
	if bytes.Equal(cur, want) {
		m.health.SetHealthy(resolvTrampleWarnable)
		if lastWarn != nil {
			m.mu.Lock()
			m.lastWarnContents = nil
			m.mu.Unlock()
			m.logf("trample: resolv.conf again matches expected content")
		}
		return
	}
	if bytes.Equal(cur, lastWarn) {
		// We already logged about this, so not worth doing it again.
		return
	}

	m.mu.Lock()
	m.lastWarnContents = cur
	m.mu.Unlock()

	show := cur
	if len(show) > 1024 {
		show = show[:1024]
	}
	m.logf("trample: resolv.conf changed from what we expected. did some other program interfere? current contents: %q", show)
	m.health.SetUnhealthy(resolvTrampleWarnable, nil)
}
