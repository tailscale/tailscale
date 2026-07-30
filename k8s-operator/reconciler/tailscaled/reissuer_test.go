// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailscaled_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"

	tailscaleclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/k8s-operator/tsclient"
	"tailscale.com/kube/kubetypes"
)

func TestReissuer_ShouldReissue(t *testing.T) {
	existingAuthKey := "existing-auth-key"

	for name, tc := range map[string]struct {
		stateData   map[string][]byte
		cfgAuthKey  *string
		wantReissue bool
		wantDeleted []string
	}{
		"no_state_no_request": {
			cfgAuthKey: &existingAuthKey,
		},
		"no_reissue_request": {
			stateData:  map[string][]byte{kubetypes.KeyDeviceID: []byte("nodeid-0")},
			cfgAuthKey: &existingAuthKey,
		},
		"reissue_requested_key_still_current_waits": {
			// Reissue requested but the config's key differs from the broken
			// one: a fresh key was already written and the replica hasn't
			// picked it up yet.
			stateData: map[string][]byte{
				kubetypes.KeyReissueAuthkey: []byte("some-older-authkey"),
			},
			cfgAuthKey: &existingAuthKey,
		},
		"reissue_requested_broken_key_reissues": {
			stateData: map[string][]byte{
				kubetypes.KeyDeviceID:       []byte("nodeid-0"),
				kubetypes.KeyReissueAuthkey: []byte(existingAuthKey),
			},
			cfgAuthKey:  &existingAuthKey,
			wantReissue: true,
			wantDeleted: []string{"nodeid-0"},
		},
		"reissue_requested_empty_key_reissues_no_device": {
			// Reissue requested, config key empty, and no device_id yet: reissue
			// but nothing to delete from control.
			stateData: map[string][]byte{
				kubetypes.KeyReissueAuthkey: []byte(""),
			},
			cfgAuthKey:  nil,
			wantReissue: true,
			wantDeleted: nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var stateSecret *corev1.Secret
			if tc.stateData != nil {
				stateSecret = &corev1.Secret{Data: tc.stateData}
			}

			tsc := &fakeReissueClient{}
			r := tailscaled.NewReissuer()
			r.EnsureState("pg", 1)

			got, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), tailscaled.ReissueInput{
				ParentName:  "pg",
				ReplicaName: "pg-0",
				Kind:        tailscaled.KindProxyGroup,
				StateSecret: stateSecret,
				CfgAuthKey:  tc.cfgAuthKey,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantReissue {
				t.Errorf("shouldReissue = %v, want %v", got, tc.wantReissue)
			}
			if !slices.Equal(tsc.deleted, tc.wantDeleted) {
				t.Errorf("deleted devices = %v, want %v", tsc.deleted, tc.wantDeleted)
			}
		})
	}
}

// TestReissuer_InFlight verifies that once a reissue is triggered, subsequent
// checks return false until the replica clears the reissue request from its
// state Secret.
func TestReissuer_InFlight(t *testing.T) {
	key := "broken-key"
	tsc := &fakeReissueClient{}
	r := tailscaled.NewReissuer()
	r.EnsureState("pg", 1)

	requested := &corev1.Secret{Data: map[string][]byte{
		kubetypes.KeyDeviceID:       []byte("nodeid-0"),
		kubetypes.KeyReissueAuthkey: []byte(key),
	}}

	in := tailscaled.ReissueInput{ParentName: "pg", ReplicaName: "pg-0", Kind: tailscaled.KindProxyGroup, StateSecret: requested, CfgAuthKey: &key}

	got, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), in)
	if err != nil || !got {
		t.Fatalf("first check: got %v, err %v; want true, nil", got, err)
	}

	// Request still present -> reissue is in-flight, don't reissue again.
	got, err = r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), in)
	if err != nil || got {
		t.Fatalf("in-flight check: got %v, err %v; want false, nil", got, err)
	}

	// Request cleared by containerboot -> in-flight marker resets, no reissue.
	cleared := &corev1.Secret{Data: map[string][]byte{kubetypes.KeyDeviceID: []byte("nodeid-1")}}
	got, err = r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), tailscaled.ReissueInput{
		ParentName: "pg", ReplicaName: "pg-0", Kind: tailscaled.KindProxyGroup, StateSecret: cleared, CfgAuthKey: &key,
	})
	if err != nil || got {
		t.Fatalf("cleared check: got %v, err %v; want false, nil", got, err)
	}
}

// TestReissuer_RateLimit verifies that the per-parent rate limiter, shared
// across replicas, blocks re-issuance once its burst is exhausted.
func TestReissuer_RateLimit(t *testing.T) {
	key := "broken-key"
	tsc := &fakeReissueClient{}
	r := tailscaled.NewReissuer()
	// Burst of 1: the first replica's reissue consumes the only token.
	r.EnsureState("pg", 1)

	brokenState := func() *corev1.Secret {
		return &corev1.Secret{Data: map[string][]byte{
			kubetypes.KeyDeviceID:       []byte("nodeid"),
			kubetypes.KeyReissueAuthkey: []byte(key),
		}}
	}

	if got, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), tailscaled.ReissueInput{
		ParentName: "pg", ReplicaName: "pg-0", Kind: tailscaled.KindProxyGroup, StateSecret: brokenState(), CfgAuthKey: &key,
	}); err != nil || !got {
		t.Fatalf("first replica: got %v, err %v; want true, nil", got, err)
	}

	// A second replica sharing the parent's limiter finds the bucket empty.
	_, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), tailscaled.ReissueInput{
		ParentName: "pg", ReplicaName: "pg-1", Kind: tailscaled.KindProxyGroup, StateSecret: brokenState(), CfgAuthKey: &key,
	})
	if err == nil || !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Fatalf("second replica: expected rate limit error, got %v", err)
	}
}

// TestReissuer_ShouldReissue_NoEnsureState verifies ShouldReissue creates the
// rate limiter on demand, so a caller that reaches it without a prior
// EnsureState reissues instead of panicking on a nil limiter.
func TestReissuer_ShouldReissue_NoEnsureState(t *testing.T) {
	key := "broken-key"
	tsc := &fakeReissueClient{}
	r := tailscaled.NewReissuer()

	broken := &corev1.Secret{Data: map[string][]byte{
		kubetypes.KeyDeviceID:       []byte("nodeid-0"),
		kubetypes.KeyReissueAuthkey: []byte(key),
	}}

	got, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), tailscaled.ReissueInput{
		ParentName: "pg", ReplicaName: "pg-0", Kind: tailscaled.KindProxyGroup, StateSecret: broken, CfgAuthKey: &key,
	})
	if err != nil || !got {
		t.Fatalf("got %v, err %v; want true, nil", got, err)
	}
	if !slices.Equal(tsc.deleted, []string{"nodeid-0"}) {
		t.Errorf("deleted devices = %v, want [nodeid-0]", tsc.deleted)
	}
}

// TestReissuer_RemoveState verifies that after RemoveState the in-flight marker
// is cleared, so a later reissue request for the same replica triggers afresh.
func TestReissuer_RemoveState(t *testing.T) {
	key := "broken-key"
	tsc := &fakeReissueClient{}
	r := tailscaled.NewReissuer()
	r.EnsureState("pg", 1)

	broken := func() *corev1.Secret {
		return &corev1.Secret{Data: map[string][]byte{
			kubetypes.KeyDeviceID:       []byte("nodeid-0"),
			kubetypes.KeyReissueAuthkey: []byte(key),
		}}
	}
	in := tailscaled.ReissueInput{ParentName: "pg", ReplicaName: "pg-0", Kind: tailscaled.KindProxyGroup, StateSecret: broken(), CfgAuthKey: &key}

	if got, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), in); err != nil || !got {
		t.Fatalf("first check: got %v, err %v; want true, nil", got, err)
	}

	// Same request still present: in-flight marker suppresses a second reissue.
	if got, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), in); err != nil || got {
		t.Fatalf("in-flight check: got %v, err %v; want false, nil", got, err)
	}

	// RemoveState drops the in-flight marker (and the rate limiter), so the next
	// call is treated as a fresh reissue rather than an in-flight one.
	r.RemoveState("pg")
	if got, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), in); err != nil || !got {
		t.Fatalf("after RemoveState: got %v, err %v; want true, nil", got, err)
	}
}

// TestReissuer_RemoveState_AfterScaleDown verifies RemoveState clears markers
// for every replica the parent ever had, not just its current count, so a
// parent scaled down then deleted doesn't strand in-flight entries.
func TestReissuer_RemoveState_AfterScaleDown(t *testing.T) {
	key := "broken-key"
	tsc := &fakeReissueClient{}
	r := tailscaled.NewReissuer()
	r.EnsureState("pg", 2)

	broken := func(replica string) tailscaled.ReissueInput {
		return tailscaled.ReissueInput{
			ParentName:  "pg",
			ReplicaName: replica,
			Kind:        tailscaled.KindProxyGroup,
			StateSecret: &corev1.Secret{Data: map[string][]byte{
				kubetypes.KeyDeviceID:       []byte("nodeid"),
				kubetypes.KeyReissueAuthkey: []byte(key),
			}},
			CfgAuthKey: &key,
		}
	}

	// Both replicas start a reissue, then the parent scales down to one.
	if got, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), broken("pg-0")); err != nil || !got {
		t.Fatalf("pg-0: got %v, err %v; want true, nil", got, err)
	}
	if got, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), broken("pg-1")); err != nil || !got {
		t.Fatalf("pg-1: got %v, err %v; want true, nil", got, err)
	}

	// Deleting the parent must clear pg-1's marker too, even though the caller
	// no longer knows about the scaled-away replica. A fresh Reissuer with the
	// same parent must see pg-1 as not in-flight; we assert via RemoveState then
	// a reissue that succeeds (an uncleared marker would suppress it).
	r.RemoveState("pg")
	if got, err := r.ShouldReissue(t.Context(), tsc, zap.NewNop().Sugar(), broken("pg-1")); err != nil || !got {
		t.Fatalf("pg-1 after RemoveState: got %v, err %v; want true, nil", got, err)
	}
}

type fakeReissueClient struct {
	tsclient.Client

	mu      sync.Mutex
	deleted []string
}

func (c *fakeReissueClient) Devices() tsclient.DeviceResource { return (*fakeReissueDevices)(c) }

type fakeReissueDevices fakeReissueClient

func (d *fakeReissueDevices) Delete(_ context.Context, id string) error {
	c := (*fakeReissueClient)(d)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleted = append(c.deleted, id)
	return nil
}

func (d *fakeReissueDevices) List(_ context.Context, _ ...tailscaleclient.ListDevicesOptions) ([]tailscaleclient.Device, error) {
	return nil, nil
}

func (d *fakeReissueDevices) Get(_ context.Context, _ string) (*tailscaleclient.Device, error) {
	return nil, nil
}
