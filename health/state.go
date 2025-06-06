// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package health

import (
	"time"

	"tailscale.com/tailcfg"
)

// State contains the health status of the backend, and is
// provided to the client UI via LocalAPI through ipn.Notify.
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
	if t.nil() {
		return &State{}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.warnableVal == nil || len(t.warnableVal) == 0 {
		return &State{}
	}

	wm := map[WarnableCode]UnhealthyState{}

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
		wm[w.Code] = *w.unhealthyState(ws)
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

		wm[state.WarnableCode] = state
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
