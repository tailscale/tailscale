// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package health

import (
	"time"
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
// that a Warnable is currently unhealthy.
type UnhealthyState struct {
	WarnableCode        WarnableCode
	Severity            Severity
	Title               string
	Text                string
	BrokenSince         *time.Time     `json:",omitempty"`
	Args                Args           `json:",omitempty"`
	DependsOn           []WarnableCode `json:",omitempty"`
	ImpactsConnectivity bool           `json:",omitempty"`
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
		if !w.IsVisible(ws) {
			// Skip invisible Warnables.
			continue
		}
		wm[w.Code] = *w.unhealthyState(ws)
	}

	return &State{
		Warnings: wm,
	}
}
