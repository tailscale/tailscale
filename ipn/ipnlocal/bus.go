// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tstime"
)

type rateLimitingBusSender struct {
	fn              func(*ipn.Notify) (keepGoing bool)
	lastFlush       time.Time           // last call to fn, or zero value if none
	interval        time.Duration       // 0 to flush immediately; non-zero to rate limit sends
	clock           tstime.DefaultClock // non-nil for testing
	didSendTestHook func()              // non-nil for testing

	// pending, if non-nil, is the pending notification that we
	// haven't sent yet. We own this memory to mutate.
	pending *ipn.Notify

	// flushTimer is non-nil if the timer is armed.
	flushTimer  tstime.TimerController // effectively a *time.Timer
	flushTimerC <-chan time.Time       // ... said ~Timer's C chan
}

func (s *rateLimitingBusSender) close() {
	if s.flushTimer != nil {
		s.flushTimer.Stop()
	}
}

func (s *rateLimitingBusSender) flushChan() <-chan time.Time {
	return s.flushTimerC
}

func (s *rateLimitingBusSender) flush() (keepGoing bool) {
	if n := s.pending; n != nil {
		s.pending = nil
		return s.flushNotify(n)
	}
	return true
}

func (s *rateLimitingBusSender) flushNotify(n *ipn.Notify) (keepGoing bool) {
	s.lastFlush = s.clock.Now()
	return s.fn(n)
}

// send conditionally sends n to the underlying fn, possibly rate
// limiting it, depending on whether s.interval is set, and whether
// n is a notable notification that the client (typically a GUI) would
// want to act on (render) immediately.
//
// It returns whether the caller should keep looping.
//
// The passed-in memory 'n' is owned by the caller and should
// not be mutated.
func (s *rateLimitingBusSender) send(n *ipn.Notify) (keepGoing bool) {
	if s.interval <= 0 {
		// No rate limiting case.
		return s.fn(n)
	}
	if isNotableNotify(n) {
		// Notable notifications are always sent immediately.
		// But first send any boring one that was pending.
		// TODO(bradfitz): there might be a boring one pending
		// with a NetMap or Engine field that is redundant
		// with the new one (n) with NetMap or Engine populated.
		// We should clear the pending one's NetMap/Engine in
		// that case. Or really, merge the two, but mergeBoringNotifies
		// only handles the case of both sides being boring.
		// So for now, flush both.
		if !s.flush() {
			return false
		}
		return s.flushNotify(n)
	}
	s.pending = mergeBoringNotifies(s.pending, n)
	d := s.clock.Now().Sub(s.lastFlush)
	if d > s.interval {
		return s.flush()
	}
	nextFlushIn := s.interval - d
	if s.flushTimer == nil {
		s.flushTimer, s.flushTimerC = s.clock.NewTimer(nextFlushIn)
	} else {
		s.flushTimer.Reset(nextFlushIn)
	}
	return true
}

func (s *rateLimitingBusSender) Run(ctx context.Context, ch <-chan *ipn.Notify) {
	for {
		select {
		case <-ctx.Done():
			return
		case n, ok := <-ch:
			if !ok {
				return
			}
			if !s.send(n) {
				return
			}
			if f := s.didSendTestHook; f != nil {
				f()
			}
		case <-s.flushChan():
			if !s.flush() {
				return
			}
		}
	}
}

// mergeBoringNotify merges new notify 'src' into possibly-nil 'dst',
// either mutating 'dst' or allocating a new one if 'dst' is nil,
// returning the merged result.
//
// dst and src must both be "boring" (i.e. not notable per isNotifiableNotify).
func mergeBoringNotifies(dst, src *ipn.Notify) *ipn.Notify {
	if dst == nil {
		dst = &ipn.Notify{Version: src.Version}
	}
	if src.NetMap != nil {
		dst.NetMap = src.NetMap
	}
	if src.Engine != nil {
		dst.Engine = src.Engine
	}
	return dst
}

// isNotableNotify reports whether n is a "notable" notification that
// should be sent on the IPN bus immediately (e.g. to GUIs) without
// rate limiting it for a few seconds.
//
// It effectively reports whether n contains any field set that's
// not NetMap or Engine.
func isNotableNotify(n *ipn.Notify) bool {
	if n == nil {
		return false
	}
	return n.State != nil ||
		n.SessionID != "" ||
		n.BrowseToURL != nil ||
		n.LocalTCPPort != nil ||
		n.ClientVersion != nil ||
		n.Prefs != nil ||
		n.ErrMessage != nil ||
		n.LoginFinished != nil ||
		!n.DriveShares.IsNil() ||
		n.Health != nil ||
		len(n.IncomingFiles) > 0 ||
		len(n.OutgoingFiles) > 0 ||
		n.FilesWaiting != nil ||
		n.SuggestedExitNode != nil
}
