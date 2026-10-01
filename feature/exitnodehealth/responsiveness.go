// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package exitnodehealth

import (
	"fmt"
	"sync"
	"time"

	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/tsconst"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/wgint"
)

const exitNodeResponseTimeout = time.Minute

// ArgLastResponseTime is the UTC RFC3339 time of the last response, or the
// start of monitoring if no response has been received.
const ArgLastResponseTime health.Arg = "last-response-time"

var exitNodeUnresponsiveWarnable = health.Register(&health.Warnable{
	Code:                tsconst.HealthWarnableExitNodeUnresponsive,
	Title:               "Exit node unresponsive",
	Severity:            health.SeverityHigh,
	DependsOn:           []*health.Warnable{health.IPNStateWarnable, health.NetworkStatusWarnable},
	ImpactsConnectivity: true,
	Text: func(args health.Args) string {
		return fmt.Sprintf("The currently selected exit node %q has not responded since %s.", args[ArgExitNodeName], args[ArgLastResponseTime])
	},
})

// Only the feature retains history, for the selected exit node alone.
type responsiveness struct {
	key                            key.NodePublic
	name                           string
	started, checked, lastResponse mono.Time
	idle                           bool
	window                         time.Duration
	txBytes, rxBytes               uint64
	lastTx, lastRx                 mono.Time
}

var activityObservers sync.Map // *magicsock.Conn -> *extension

func observerFor(c *magicsock.Conn) *extension {
	if v, ok := activityObservers.Load(c); ok {
		return v.(*extension)
	}
	return nil
}

func reportExitNodeHeartbeatStateLocked(c *magicsock.Conn, k key.NodePublic, now mono.Time, idle, pong bool, window time.Duration) {
	if e := observerFor(c); e != nil {
		e.recordActivity(k, now, idle, pong, window)
	}
}

// Counter lookup occurs only in the outside-lock hook. The inside-lock hook
// records state but never publishes an unresponsive transition before this
// filter has had a chance to check working traffic.
func checkExitNodeResponsiveness(c *magicsock.Conn, k key.NodePublic, getPeer func(key.NodePublic) (wgint.Peer, bool)) {
	e := observerFor(c)
	if e == nil {
		return
	}
	e.mu.Lock()
	s := &e.responsiveness
	if e.closed || s.key.IsZero() || s.key != k || s.idle {
		e.mu.Unlock()
		return
	}
	checked := s.checked
	e.mu.Unlock()
	var sampled bool
	var tx, rx uint64
	if getPeer != nil {
		if p, ok := getPeer(k); ok && p.IsValid() {
			sampled = true
			tx, rx = p.TxBytes(), p.RxBytes()
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s = &e.responsiveness
	if e.closed || s.key != k || s.idle || s.checked != checked {
		return
	}
	if sampled {
		e.observeTraffic(tx, rx, checked)
	}
	e.evaluateResponsiveness(checked)
}

func (e *extension) updateResponsivenessSelectionLocked(c healthContext) {
	var k key.NodePublic
	name := ""
	if c.NetworkConfigured && c.Prefs.Valid() && c.Prefs.WantRunning() &&
		(c.State == ipn.Running || c.State == ipn.Starting) &&
		c.Peer.Valid() && !c.Peer.IsWireGuardOnly() && !c.Peer.DiscoKey().IsZero() {
		if reason, n := evaluateExitNodeStatus(c); reason == ExitNodeOK {
			k, name = c.Peer.Key(), n
		}
	}
	if k != e.responsiveness.key {
		e.responsiveness = responsiveness{key: k, started: mono.Now(), idle: true}
		e.health.SetHealthy(exitNodeUnresponsiveWarnable)
	}
	e.responsiveness.name = name
	if e.magicsock != nil {
		if k.IsZero() {
			activityObservers.Delete(e.magicsock)
		} else {
			activityObservers.Store(e.magicsock, e)
		}
	}
}

func (e *extension) recordActivity(k key.NodePublic, now mono.Time, idle, pong bool, window time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := &e.responsiveness
	if e.closed || s.key.IsZero() || s.key != k {
		return
	}
	if pong {
		if s.lastResponse.IsZero() || now.After(s.lastResponse) {
			s.lastResponse = now
		}
		e.health.SetHealthy(exitNodeUnresponsiveWarnable)
		return
	}
	if !s.checked.IsZero() && now.Before(s.checked) {
		return
	}
	if idle {
		s.started = 0
		e.health.SetHealthy(exitNodeUnresponsiveWarnable)
	} else if s.idle || s.started.IsZero() || (!s.checked.IsZero() && now.Sub(s.checked) > window) {
		// Give each active period a full response timeout, including the first
		// heartbeat after selection when no idle heartbeat has been observed.
		s.started = now
	}
	s.idle, s.checked, s.window = idle, now, window
}

// observeTraffic requires e.mu. Changes, not historical totals, provide the
// best-effort guard; unidirectional traffic does not prove a round trip.
func (e *extension) observeTraffic(tx, rx uint64, now mono.Time) {
	s := &e.responsiveness
	// Nonzero counter changes, including decreases, count as activity.
	// A reset to zero is not evidence that packets have been exchanged.
	if tx != 0 && tx != s.txBytes {
		s.lastTx = now
	}
	if rx != 0 && rx != s.rxBytes {
		s.lastRx = now
	}
	s.txBytes, s.rxBytes = tx, rx
	if !s.lastTx.IsZero() && !s.lastRx.IsZero() && now.Sub(s.lastTx) <= s.window && now.Sub(s.lastRx) <= s.window {
		if s.lastResponse.IsZero() || s.lastRx.After(s.lastResponse) {
			s.lastResponse = s.lastRx
		}
	}
}

func (e *extension) evaluateResponsiveness(now mono.Time) {
	s := &e.responsiveness
	response, baseline := s.lastResponse, s.started
	if !response.IsZero() && response.After(baseline) {
		baseline = response
	}
	if now.Sub(baseline) < exitNodeResponseTimeout {
		e.health.SetHealthy(exitNodeUnresponsiveWarnable)
		return
	}
	if response.IsZero() {
		response = s.started
	}
	name := s.name
	if name == "" {
		name = s.key.ShortString()
	}
	e.health.SetUnhealthy(exitNodeUnresponsiveWarnable, health.Args{
		ArgExitNodeName: name, ArgLastResponseTime: response.WallTime().UTC().Format(time.RFC3339),
	})
}
