// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"runtime"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/util/mak"
)

// goosGetsLegacyNetmapNotify reports whether tailscaled, when running on the
// current GOOS, still emits the legacy [ipn.Notify.NetMap] field on runtime
// (non-initial) bus messages. It is true on platforms whose host GUIs have
// not yet finished migrating to the narrower bus signals
// ([ipn.Notify.SelfChange] / [ipn.Notify.PeerChanges]) and the on-demand
// [LocalClient.NetMap] fetch.
//
// runtime.GOOS is a compile-time constant, so the producer-side code that
// builds and ships NetMap on the bus is dead-code-eliminated on Linux and
// other geese where this is false.
const goosGetsLegacyNetmapNotify = runtime.GOOS == "windows"

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

// mergeBoringNotify merges new notify src into possibly-nil dst,
// either mutating dst or allocating a new one if dst is nil,
// returning the merged result.
//
// dst and src must both be "boring" (i.e. not notable per isNotifiableNotify).
func mergeBoringNotifies(dst, src *ipn.Notify) *ipn.Notify {
	if dst == nil {
		dst = &ipn.Notify{Version: src.Version}
	}
	if goosGetsLegacyNetmapNotify && src.NetMap != nil {
		// Full netmap supersedes any accumulated peer-change deltas.
		dst.NetMap = src.NetMap
		dst.PeerChangedPatch = nil
	} else if src.PeerChangedPatch != nil {
		dst.PeerChangedPatch = mergePeerChangedPatch(dst.PeerChangedPatch, src.PeerChangedPatch)
	}
	if len(src.PeersChanged) > 0 {
		dst.PeersChanged = append(dst.PeersChanged, src.PeersChanged...)
	}
	if len(src.PeersRemoved) > 0 {
		dst.PeersRemoved = append(dst.PeersRemoved, src.PeersRemoved...)
	}
	for id, up := range src.UserProfiles {
		mak.Set(&dst.UserProfiles, id, up)
	}
	if src.Engine != nil {
		dst.Engine = src.Engine
	}
	return dst
}

// mergePeerChangedPatch merges new peer-changed patches from src into dst,
// either mutating dst or allocating a new slice if dst is nil, returning the
// merged result. Values in src override those in dst for the same NodeID.
func mergePeerChangedPatch(dst, src []*tailcfg.PeerChange) []*tailcfg.PeerChange {
	idxByNode := make(map[tailcfg.NodeID]int, len(dst))
	for i, d := range dst {
		idxByNode[d.NodeID] = i
	}

	for _, nd := range src {
		if oi, ok := idxByNode[nd.NodeID]; ok {
			dst[oi] = mergePeerChangeForIpnBus(dst[oi], nd)
			continue
		}
		idxByNode[nd.NodeID] = len(dst)
		dst = append(dst, nd)
	}
	return dst
}

// mergePeerChangeForIpnBus merges new with old, returning the result.
// Fields set in new override those in old; fields only set in old are preserved.
func mergePeerChangeForIpnBus(old, new *tailcfg.PeerChange) *tailcfg.PeerChange {
	merged := *old

	// This is a subset of PeerChange that reflects only the fields that can
	// be changed via a NodeMutation.  If future fields can be updated via
	// NodeMutations from map responses (and they are relevant to the ipn bus), then
	// they should be added here and merged in the same way.
	if new.DERPRegion != 0 {
		// netmap.NodeMutationDerpHome
		merged.DERPRegion = new.DERPRegion
	}
	if new.Online != nil {
		// netmap.NodeMutationOnline
		merged.Online = new.Online
	}
	if new.LastSeen != nil {
		// netmap.NodeMutationLastSeen
		merged.LastSeen = new.LastSeen
	}
	if new.Endpoints != nil {
		// netmap.NodeMutationEndpoints
		merged.Endpoints = new.Endpoints
	}

	return &merged
}

// isNotableNotify reports whether n is a "notable" notification that
// should be sent on the IPN bus immediately (e.g. to GUIs) without
// rate limiting it for a few seconds.
//
// This is only used for legacy [ipn.NotifyRateLimit] subscribers. New-style
// subscriptions that receive delta streams are rejected by
// [ipn.ValidateNotifyWatchOpt] when combined with NotifyRateLimit.
//
// Legacy NetMap and Engine are the only "boring" (rate-limitable) fields.
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
		n.SelfChange != nil ||
		n.InitialStatus != nil ||
		len(n.PeerChangedPatch) > 0 ||
		len(n.PeersChanged) > 0 ||
		len(n.PeersRemoved) > 0 ||
		len(n.UserProfiles) > 0 ||
		len(n.PeerState) > 0 ||
		!n.DriveShares.IsNil() ||
		n.Health != nil ||
		len(n.IncomingFiles) > 0 ||
		len(n.OutgoingFiles) > 0 ||
		n.FilesWaiting != nil ||
		n.SuggestedExitNode != nil ||
		n.Policy != nil
}
