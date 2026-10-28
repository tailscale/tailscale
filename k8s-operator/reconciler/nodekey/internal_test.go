// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package nodekey

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var fakeOperatorPublic = key.NewTLPrivate().Public()

var _ LocalClient = (*fakeLocalClient)(nil)

func newFakeLocalClient() *fakeLocalClient {
	return &fakeLocalClient{
		networkLockStatus: &ipnstate.TailnetLockStatus{
			Enabled:   true,
			PublicKey: fakeOperatorPublic,
			TrustedKeys: []ipnstate.TKAKey{
				{Key: fakeOperatorPublic},
			},
			VisiblePeers:  make([]*ipnstate.TKAPeer, 0),
			FilteredPeers: make([]*ipnstate.TKAPeer, 0),
		},
	}
}

type fakeLocalClient struct {
	networkLockStatus *ipnstate.TailnetLockStatus
	signResult        error
}

func (f *fakeLocalClient) NetworkLockSign(ctx context.Context, nodeKey key.NodePublic, verifier []byte) error {
	return f.signResult
}

func (f *fakeLocalClient) NetworkLockStatus(ctx context.Context) (*ipnstate.NetworkLockStatus, error) {
	return f.networkLockStatus, nil
}

func TestReconciler_signNodeKey(t *testing.T) {
	var (
		ctx         = context.TODO()
		nodeID      = "fake-node-id"
		nodeTKAPeer = &ipnstate.TKAPeer{
			StableID: tailcfg.StableNodeID(nodeID),
			NodeKey:  key.NewNode().Public(),
		}
		signingError = fmt.Errorf("signing error")
	)
	tests := []struct {
		name          string
		mutationFn    func(*fakeLocalClient, *corev1.Secret)
		expectedDone  bool
		expectedError error
		expectedLogs  []string
	}{
		{
			name: "network_unlocked",
			mutationFn: func(lc *fakeLocalClient, _ *corev1.Secret) {
				lc.networkLockStatus.Enabled = false
			},
			expectedDone:  true,
			expectedError: nil,
			expectedLogs:  []string{"Tailnet is not locked, skipping node key signing"},
		},
		{
			name: "device_is_visible_peer",
			mutationFn: func(lc *fakeLocalClient, _ *corev1.Secret) {
				lc.networkLockStatus.VisiblePeers = []*ipnstate.TKAPeer{nodeTKAPeer}
			},
			expectedDone:  true,
			expectedError: nil,
			expectedLogs:  []string{},
		},
		{
			name: "operator_key_not_trusted",
			mutationFn: func(lc *fakeLocalClient, _ *corev1.Secret) {
				lc.networkLockStatus.TrustedKeys = nil
			},
			expectedDone:  true,
			expectedError: errOperatorUntrusted,
			expectedLogs: []string{
				fmt.Sprintf("Operator key is not trusted by the network. Add %q to the trusted signer keys", fakeOperatorPublic.CLIString()),
			},
		},
		{
			name: "device_not_ready",
			mutationFn: func(_ *fakeLocalClient, sec *corev1.Secret) {
				delete(sec.Data, kubetypes.KeyDeviceID)
			},
			expectedDone:  false,
			expectedError: nil,
			expectedLogs:  []string{"NodeID is empty. It may not be populated yet"},
		},
		{
			name:          "device_not_filtered_peer",
			mutationFn:    func(_ *fakeLocalClient, _ *corev1.Secret) {},
			expectedDone:  false,
			expectedError: nil,
			expectedLogs: []string{
				fmt.Sprintf("Device %q is not found in filtered peers list, deferring signing", nodeID),
			},
		},
		{
			name: "successful_signing",
			mutationFn: func(lc *fakeLocalClient, _ *corev1.Secret) {
				lc.networkLockStatus.FilteredPeers = []*ipnstate.TKAPeer{nodeTKAPeer}
			},
			expectedDone:  true,
			expectedError: nil,
			expectedLogs: []string{
				fmt.Sprintf("Network is locked. Attempting to sign device node key with operator key %q", fakeOperatorPublic.CLIString()),
			},
		},
		{
			name: "signing_error",
			mutationFn: func(lc *fakeLocalClient, _ *corev1.Secret) {
				lc.networkLockStatus.FilteredPeers = []*ipnstate.TKAPeer{nodeTKAPeer}
				lc.signResult = signingError
			},
			expectedDone:  true,
			expectedError: signingError,
			expectedLogs: []string{
				fmt.Sprintf("Network is locked. Attempting to sign device node key with operator key %q", fakeOperatorPublic.CLIString()),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observerCore, observedLogs := observer.New(zapcore.DebugLevel)
			logger := zap.New(observerCore).Sugar()

			secret := &corev1.Secret{
				Data: map[string][]byte{
					kubetypes.KeyDeviceID: []byte(nodeID),
				},
			}

			lc := newFakeLocalClient()
			tt.mutationFn(lc, secret)
			r := &Reconciler{
				localClient: lc,
			}

			done, err := r.signNodeKey(ctx, logger, secret)
			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("unexpected error: %v", err)
			}
			if done != tt.expectedDone {
				t.Errorf("unexpected retry")
			}
			if len(observedLogs.All()) != len(tt.expectedLogs) {
				t.Errorf("unexpected number of logs: %v", observedLogs.All())
			}
			for i, log := range observedLogs.All() {
				if log.Message != tt.expectedLogs[i] {
					t.Errorf("unexpected log: %v", log.Message)
				}
			}
		})
	}
}

func TestManagedSecretHandler(t *testing.T) {
	const ns = "tailscale"
	tests := []struct {
		name      string
		namespace string
		labels    map[string]string
		wantQueue bool
	}{
		{
			name:      "managed_secret_in_operator_namespace",
			namespace: ns,
			labels:    map[string]string{kubetypes.LabelManaged: "true"},
			wantQueue: true,
		},
		{
			name:      "managed_secret_in_other_namespace",
			namespace: "other",
			labels:    map[string]string{kubetypes.LabelManaged: "true"},
			wantQueue: false,
		},
		{
			name:      "unmanaged_secret_in_operator_namespace",
			namespace: ns,
			labels:    nil,
			wantQueue: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: tt.namespace,
					Labels:    tt.labels,
				},
			}

			reqs := managedSecretHandler(ns)(context.TODO(), secret)
			if !tt.wantQueue {
				if len(reqs) != 0 {
					t.Fatalf("expected no requests, got %v", reqs)
				}
				return
			}

			want := reconcile.Request{}
			want.Name = secret.Name
			want.Namespace = secret.Namespace
			if len(reqs) != 1 || reqs[0] != want {
				t.Fatalf("expected [%v], got %v", want, reqs)
			}
		})
	}
}
