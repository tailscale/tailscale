// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"

	"tailscale.com/health"
)

func (m *directManager) runFileWatcher() {
	<-m.ctx.Done()
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
