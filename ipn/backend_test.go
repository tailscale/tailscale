// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"testing"

	"tailscale.com/health"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
)

func TestNotifyString(t *testing.T) {
	for _, tt := range []struct {
		name     string
		value    Notify
		expected string
	}{
		{
			name:     "notify-empty",
			value:    Notify{},
			expected: "Notify{}",
		},
		{
			name:     "notify-with-login-finished",
			value:    Notify{LoginFinished: &empty.Message{}},
			expected: "Notify{LoginFinished}",
		},
		{
			name:     "notify-with-multiple-fields",
			value:    Notify{LoginFinished: &empty.Message{}, Health: &health.State{}},
			expected: "Notify{LoginFinished Health{...}}",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.value.String()
			if actual != tt.expected {
				t.Fatalf("expected=%q, actual=%q", tt.expected, actual)
			}
		})
	}
}

// ===== State Tests =====

func TestState_String(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{NoState, "NoState"},
		{InUseOtherUser, "InUseOtherUser"},
		{NeedsLogin, "NeedsLogin"},
		{NeedsMachineAuth, "NeedsMachineAuth"},
		{Stopped, "Stopped"},
		{Starting, "Starting"},
		{Running, "Running"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.state.String()
			if got != tt.expected {
				t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.expected)
			}
		})
	}
}

func TestState_Values(t *testing.T) {
	// Test that all state values are distinct
	states := []State{NoState, InUseOtherUser, NeedsLogin, NeedsMachineAuth, Stopped, Starting, Running}
	seen := make(map[State]bool)

	for _, s := range states {
		if seen[s] {
			t.Errorf("duplicate state value: %v", s)
		}
		seen[s] = true
	}
}

func TestState_Transitions(t *testing.T) {
	// Test common state transitions make sense
	tests := []struct {
		name  string
		from  State
		to    State
		valid bool
	}{
		{"stopped_to_starting", Stopped, Starting, true},
		{"starting_to_running", Starting, Running, true},
		{"running_to_stopped", Running, Stopped, true},
		{"needs_login_to_starting", NeedsLogin, Starting, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify states are different (basic sanity)
			if tt.from == tt.to {
				t.Errorf("transition from %v to %v: states are the same", tt.from, tt.to)
			}
		})
	}
}

// ===== EngineStatus Tests =====

func TestEngineStatus(t *testing.T) {
	es := EngineStatus{
		RBytes:    1000,
		WBytes:    2000,
		NumLive:   5,
		LiveDERPs: 2,
		LivePeers: make(map[key.NodePublic]ipnstate.PeerStatusLite),
	}

	if es.RBytes != 1000 {
		t.Errorf("RBytes = %d, want 1000", es.RBytes)
	}
	if es.WBytes != 2000 {
		t.Errorf("WBytes = %d, want 2000", es.WBytes)
	}
	if es.NumLive != 5 {
		t.Errorf("NumLive = %d, want 5", es.NumLive)
	}
	if es.LiveDERPs != 2 {
		t.Errorf("LiveDERPs = %d, want 2", es.LiveDERPs)
	}
}

func TestEngineStatus_ZeroValues(t *testing.T) {
	var es EngineStatus
	if es.RBytes != 0 {
		t.Errorf("zero EngineStatus.RBytes = %d, want 0", es.RBytes)
	}
	if es.WBytes != 0 {
		t.Errorf("zero EngineStatus.WBytes = %d, want 0", es.WBytes)
	}
	if es.NumLive != 0 {
		t.Errorf("zero EngineStatus.NumLive = %d, want 0", es.NumLive)
	}
}

// ===== NotifyWatchOpt Tests =====

func TestNotifyWatchOpt_Constants(t *testing.T) {
	// Verify all constants are distinct powers of 2 (can be OR'd together)
	opts := []NotifyWatchOpt{
		NotifyWatchEngineUpdates,
		NotifyInitialState,
		NotifyInitialPrefs,
		NotifyInitialNetMap,
		NotifyNoPrivateKeys,
		NotifyInitialDriveShares,
		NotifyInitialOutgoingFiles,
		NotifyInitialHealthState,
		NotifyRateLimit,
		NotifyHealthActions,
		NotifyInitialSuggestedExitNode,
	}

	seen := make(map[NotifyWatchOpt]bool)
	for _, opt := range opts {
		if seen[opt] {
			t.Errorf("duplicate NotifyWatchOpt value: %d", opt)
		}
		seen[opt] = true

		// Verify it's a power of 2 (single bit set)
		if opt != 0 && (opt&(opt-1)) != 0 {
			t.Errorf("NotifyWatchOpt %d is not a power of 2", opt)
		}
	}
}

func TestNotifyWatchOpt_Combinations(t *testing.T) {
	// Test combining multiple options
	combined := NotifyWatchEngineUpdates | NotifyInitialState | NotifyInitialPrefs

	// Check that all bits are set
	if combined&NotifyWatchEngineUpdates == 0 {
		t.Error("combined should include NotifyWatchEngineUpdates")
	}
	if combined&NotifyInitialState == 0 {
		t.Error("combined should include NotifyInitialState")
	}
	if combined&NotifyInitialPrefs == 0 {
		t.Error("combined should include NotifyInitialPrefs")
	}

	// Check that other bits are not set
	if combined&NotifyInitialNetMap != 0 {
		t.Error("combined should not include NotifyInitialNetMap")
	}
}

func TestNotifyWatchOpt_BitwiseOperations(t *testing.T) {
	var opts NotifyWatchOpt

	// Start with nothing
	if opts != 0 {
		t.Errorf("initial opts = %d, want 0", opts)
	}

	// Add NotifyWatchEngineUpdates
	opts |= NotifyWatchEngineUpdates
	if opts&NotifyWatchEngineUpdates == 0 {
		t.Error("should have NotifyWatchEngineUpdates set")
	}

	// Add NotifyInitialState
	opts |= NotifyInitialState
	if opts&NotifyInitialState == 0 {
		t.Error("should have NotifyInitialState set")
	}

	// Both should still be set
	if opts&NotifyWatchEngineUpdates == 0 {
		t.Error("should still have NotifyWatchEngineUpdates set")
	}
}

// ===== GoogleIDTokenType Tests =====

func TestGoogleIDTokenType(t *testing.T) {
	expected := "ts_android_google_login"
	if GoogleIDTokenType != expected {
		t.Errorf("GoogleIDTokenType = %q, want %q", GoogleIDTokenType, expected)
	}
}

// ===== Notify Field Tests =====

func TestNotify_WithVersion(t *testing.T) {
	n := Notify{Version: "1.2.3"}
	s := n.String()
	if s != "Notify{Version=\"1.2.3\"}" {
		t.Errorf("Notify with version: got %q", s)
	}
}

func TestNotify_WithState(t *testing.T) {
	state := Running
	n := Notify{State: &state}
	s := n.String()
	if s == "Notify{}" {
		t.Error("Notify with State should not be empty string")
	}
}

func TestNotify_WithErr(t *testing.T) {
	errMsg := "test error"
	n := Notify{ErrMessage: &errMsg}
	s := n.String()
	if s == "Notify{}" {
		t.Error("Notify with ErrMessage should not be empty string")
	}
}

func TestNotify_MultipleFields(t *testing.T) {
	state := Running
	errMsg := "error"
	n := Notify{
		Version:      "1.0.0",
		State:        &state,
		ErrMessage:   &errMsg,
		LoginFinished: &empty.Message{},
	}
	s := n.String()

	// Should contain multiple indicators
	if s == "Notify{}" {
		t.Error("Notify with multiple fields should have non-empty string")
	}
}

// ===== Edge Cases =====

func TestState_InvalidValue(t *testing.T) {
	// Test that an invalid state value doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("State.String() panicked with invalid value: %v", r)
		}
	}()

	var s State = 999
	_ = s.String() // Should not panic
}

func TestNotifyWatchOpt_Zero(t *testing.T) {
	var opt NotifyWatchOpt
	if opt != 0 {
		t.Errorf("zero NotifyWatchOpt = %d, want 0", opt)
	}
}

func TestNotifyWatchOpt_AllBits(t *testing.T) {
	// Combine all options
	all := NotifyWatchEngineUpdates |
		NotifyInitialState |
		NotifyInitialPrefs |
		NotifyInitialNetMap |
		NotifyNoPrivateKeys |
		NotifyInitialDriveShares |
		NotifyInitialOutgoingFiles |
		NotifyInitialHealthState |
		NotifyRateLimit |
		NotifyHealthActions |
		NotifyInitialSuggestedExitNode

	// Should have multiple bits set
	if all == 0 {
		t.Error("combining all NotifyWatchOpt should be non-zero")
	}

	// Check each individual bit is present
	if all&NotifyWatchEngineUpdates == 0 {
		t.Error("all should include NotifyWatchEngineUpdates")
	}
	if all&NotifyInitialSuggestedExitNode == 0 {
		t.Error("all should include NotifyInitialSuggestedExitNode")
	}
}
