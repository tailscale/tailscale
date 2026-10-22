// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package services

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/kube/localclient"
)

func TestEnsureServicesAdvertised(t *testing.T) {
	tests := []struct {
		name      string
		current   []string
		want      []string
		wantEdits int
	}{
		{
			name:      "changed",
			current:   []string{"svc:old"},
			want:      []string{"svc:new"},
			wantEdits: 1,
		},
		{
			name:    "unchanged",
			current: []string{"svc:one", "svc:two"},
			want:    []string{"svc:one", "svc:two"},
		},
		{
			name:      "noncanonical_order",
			current:   []string{"svc:two", "svc:one"},
			want:      []string{"svc:one", "svc:two"},
			wantEdits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lc := &localclient.FakeLocalClient{
					GetPrefsResult: &ipn.Prefs{AdvertiseServices: tt.current},
				}
				start := time.Now()
				if err := EnsureServicesAdvertised(t.Context(), tt.want, lc, t.Logf); err != nil {
					t.Fatal(err)
				}
				if elapsed := time.Since(start); elapsed != 0 {
					t.Errorf("EnsureServicesAdvertised took %v, want no delay", elapsed)
				}
				if got := len(lc.EditPrefsCalls); got != tt.wantEdits {
					t.Errorf("EditPrefs calls = %d, want %d", got, tt.wantEdits)
				}
			})
		})
	}
}

func TestEnsureServicesAdvertisedGetPrefsError(t *testing.T) {
	wantErr := errors.New("get prefs")
	lc := &getPrefsErrorClient{
		FakeLocalClient: new(localclient.FakeLocalClient),
		err:             wantErr,
	}
	if err := EnsureServicesAdvertised(t.Context(), []string{"svc:test"}, lc, t.Logf); !errors.Is(err, wantErr) {
		t.Fatalf("EnsureServicesAdvertised error = %v, want %v", err, wantErr)
	}
	if got := len(lc.EditPrefsCalls); got != 0 {
		t.Errorf("EditPrefs calls = %d, want 0", got)
	}
}

type getPrefsErrorClient struct {
	*localclient.FakeLocalClient
	err error
}

func (lc *getPrefsErrorClient) GetPrefs(context.Context) (*ipn.Prefs, error) {
	return nil, lc.err
}
