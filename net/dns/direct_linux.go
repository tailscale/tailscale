// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"context"
	"errors"

	"github.com/illarion/gonotify"
	"tailscale.com/health"
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

var warnTrample = health.NewWarnable()

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
		warnTrample.Set(nil)
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
	warnTrample.Set(errors.New("Linux DNS config not ideal. /etc/resolv.conf overwritten. See https://tailscale.com/s/dns-fight"))
}

func (m *directManager) closeInotifyOnDone(ctx context.Context, in *gonotify.Inotify) {
	<-ctx.Done()
	in.Close()
}
