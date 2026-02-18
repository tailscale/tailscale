// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package health

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
)

// State contains the health status of the backend, and is
// provided to the client UI via LocalAPI through ipn.Notify.
//
// It is also exposed via c2n for debugging purposes, so try
// not to change its structure too gratuitously.
type State struct {
	// Each key-value pair in Warnings represents a Warnable that is currently
	// unhealthy. If a Warnable is healthy, it will not be present in this map.
	// When a Warnable is unhealthy and becomes healthy, its key-value pair
	// disappears in the next issued State. Observers should treat the absence of
	// a WarnableCode in this map as an indication that the Warnable became healthy,
	// and may use that to clear any notifications that were previously shown to the user.
	// If Warnings is nil, all Warnables are healthy and the backend is overall healthy.
	Warnings map[WarnableCode]UnhealthyState
}

// UnhealthyState contains information to be shown to the user to inform them
// that a [Warnable] is currently unhealthy or [tailcfg.DisplayMessage] is being
// sent from the control-plane.
type UnhealthyState struct {
	WarnableCode        WarnableCode
	Severity            Severity
	Title               string
	Text                string
	BrokenSince         *time.Time            `json:",omitempty"`
	Args                Args                  `json:",omitempty"`
	DependsOn           []WarnableCode        `json:",omitempty"`
	ImpactsConnectivity bool                  `json:",omitempty"`
	PrimaryAction       *UnhealthyStateAction `json:",omitempty"`

	// ETag identifies a specific version of an UnhealthyState. If the contents
	// of the other fields of two UnhealthyStates are the same, the ETags will
	// be the same. If the contents differ, the ETags will also differ. The
	// implementation is not defined and the value is opaque: it might be a
	// hash, it might be a simple counter. Implementations should not rely on
	// any specific implementation detail or format of the ETag string other
	// than string (in)equality.
	ETag string `json:",omitzero"`
}

// hash computes a deep hash of UnhealthyState which will be stable across
// different runs of the same binary.
func (u UnhealthyState) hash() []byte {
	hasher := sha256.New()
	enc := json.NewEncoder(hasher)

	// hash.Hash.Write never returns an error, so this will only fail if u is
	// not marshalable, in which case we have much bigger problems.
	_ = enc.Encode(u)
	return hasher.Sum(nil)
}

// withETag returns a copy of UnhealthyState with an ETag set. The ETag will be
// the same for all UnhealthyState instances that are equal. If calculating the
// ETag errors, it returns a copy of the UnhealthyState with an empty ETag.
func (u UnhealthyState) withETag() UnhealthyState {
	u.ETag = ""
	u.ETag = hex.EncodeToString(u.hash())
	return u
}

// UnhealthyStateAction represents an action (URL and link) to be presented to
// the user associated with an [UnhealthyState]. Analogous to
// [tailcfg.DisplayMessageAction].
type UnhealthyStateAction struct {
	URL   string
	Label string
}

// unhealthyState returns a unhealthyState of the Warnable given its current warningState.
func (w *Warnable) unhealthyState(ws *warningState) *UnhealthyState {
	var text string
	if ws.Args != nil {
		text = w.Text(ws.Args)
	} else {
		text = w.Text(Args{})
	}

	dependsOnWarnableCodes := make([]WarnableCode, len(w.DependsOn), len(w.DependsOn)+1)
	for i, d := range w.DependsOn {
		dependsOnWarnableCodes[i] = d.Code
	}

	if w != warmingUpWarnable {
		// Here we tell the frontend that all Warnables depend on warmingUpWarnable. GUIs will silence all warnings until all
		// their dependencies are healthy. This is a special case to prevent the GUI from showing a bunch of warnings when
		// the backend is still warming up.
		dependsOnWarnableCodes = append(dependsOnWarnableCodes, warmingUpWarnable.Code)
	}

	return &UnhealthyState{
		WarnableCode:        w.Code,
		Severity:            w.Severity,
		Title:               w.Title,
		Text:                text,
		BrokenSince:         &ws.BrokenSince,
		Args:                ws.Args,
		DependsOn:           dependsOnWarnableCodes,
		ImpactsConnectivity: w.ImpactsConnectivity,
	}
}

// CurrentState returns a snapshot of the current health status of the backend.
// It returns a State with nil Warnings if the backend is healthy (all Warnables
// have no issues).
// The returned State is a snapshot of shared memory, and the caller should not
// mutate the returned value.
func (t *Tracker) CurrentState() *State {
	if !buildfeatures.HasHealth || t.nil() {
		return &State{}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var wm map[WarnableCode]UnhealthyState

	for w, ws := range t.warnableVal {
		if !w.IsVisible(ws, t.now) {
			// Skip invisible Warnables.
			continue
		}
		if t.isEffectivelyHealthyLocked(w) {
			// Skip Warnables that are unhealthy if they have dependencies
			// that are unhealthy.
			continue
		}
		state := w.unhealthyState(ws)
		mak.Set(&wm, w.Code, state.withETag())
	}

	for id, msg := range t.lastNotifiedControlMessages {
		state := UnhealthyState{
			WarnableCode:        WarnableCode("control-health." + id),
			Severity:            severityFromTailcfg(msg.Severity),
			Title:               msg.Title,
			Text:                msg.Text,
			ImpactsConnectivity: msg.ImpactsConnectivity,
			// TODO(tailscale/corp#27759): DependsOn?
		}

		if msg.PrimaryAction != nil {
			state.PrimaryAction = &UnhealthyStateAction{
				URL:   msg.PrimaryAction.URL,
				Label: msg.PrimaryAction.Label,
			}
		}

		mak.Set(&wm, state.WarnableCode, state.withETag())
	}

	return &State{
		Warnings: wm,
	}
}

func severityFromTailcfg(s tailcfg.DisplayMessageSeverity) Severity {
	switch s {
	case tailcfg.SeverityHigh:
		return SeverityHigh
	case tailcfg.SeverityLow:
		return SeverityLow
	default:
		return SeverityMedium
	}
}

// isEffectivelyHealthyLocked reports whether w is effectively healthy.
// That means it's either actually healthy or it has a dependency that
// that's unhealthy, so we should treat w as healthy to not spam users
// with multiple warnings when only the root cause is relevant.
func (t *Tracker) isEffectivelyHealthyLocked(w *Warnable) bool {
	if _, ok := t.warnableVal[w]; !ok {
		// Warnable not found in the tracker. So healthy.
		return true
	}
	for _, d := range w.DependsOn {
		if !t.isEffectivelyHealthyLocked(d) {
			// If one of our deps is unhealthy, we're healthy.
			return true
		}
	}
	// If we have no unhealthy deps and had warnableVal set,
	// we're unhealthy.
	return false
}
