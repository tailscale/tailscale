// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"testing"

	"tailscale.com/health"
	"tailscale.com/types/empty"
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

func TestValidateNotifyWatchOpt(t *testing.T) {
	tests := []struct {
		name    string
		mask    NotifyWatchOpt
		wantErr bool
	}{
		{
			name: "legacy-rate-limit-only",
			mask: NotifyRateLimit,
		},
		{
			name: "peer-changes-without-rate-limit",
			mask: NotifyPeerChanges | NotifyPeerPatches | NotifyNoNetMap | NotifyInitialStatus,
		},
		{
			name: "in-process-no-disconnect",
			mask: NotifyInProcessNoDisconnect | NotifyPeerChanges,
		},
		{
			name:    "rate-limit-with-peer-changes",
			mask:    NotifyRateLimit | NotifyPeerChanges,
			wantErr: true,
		},
		{
			name:    "rate-limit-with-peer-patches",
			mask:    NotifyRateLimit | NotifyPeerPatches,
			wantErr: true,
		},
		{
			name:    "rate-limit-with-no-netmap",
			mask:    NotifyRateLimit | NotifyNoNetMap,
			wantErr: true,
		},
		{
			name:    "rate-limit-with-initial-status",
			mask:    NotifyRateLimit | NotifyInitialStatus,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNotifyWatchOpt(tt.mask)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("ValidateNotifyWatchOpt(%v) error = %v; wantErr %v", tt.mask, err, tt.wantErr)
			}
		})
	}
}
