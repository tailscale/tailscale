// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/ipn/ipnstate"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var (
	fakeOperatorPublic = key.NewNLPrivate().Public()
)

type fakeTSLocalClient struct {
	networkLockStatus *ipnstate.NetworkLockStatus
	signResult        error
}

var _ tsLocalClient = &fakeTSLocalClient{}

func newFakeTSLocalClient() *fakeTSLocalClient {
	return &fakeTSLocalClient{
		networkLockStatus: &ipnstate.NetworkLockStatus{
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

// NetworkLockSign implements tsLocalClient.
func (f *fakeTSLocalClient) NetworkLockSign(ctx context.Context, nodeKey key.NodePublic, verifier []byte) error {
	return f.signResult
}

// NetworkLockStatus implements tsLocalClient.
func (f *fakeTSLocalClient) NetworkLockStatus(ctx context.Context) (*ipnstate.NetworkLockStatus, error) {
	return f.networkLockStatus, nil
}

func TestNodeKeySignerReconciler_signNodeKey(t *testing.T) {
	var (
		ctx         = context.TODO()
		nodeId      = "fake-node-id"
		nodeTkaPeer = &ipnstate.TKAPeer{
			StableID: tailcfg.StableNodeID(nodeId),
			NodeKey:  key.NewNode().Public(),
		}
		signingError = fmt.Errorf("signing error")
	)
	tests := []struct {
		name          string
		mutationFn    func(*fakeTSLocalClient, *corev1.Secret)
		expectedDone  bool
		expectedError error
		expectedLogs  []string
	}{
		{
			name: "network unlocked",
			mutationFn: func(lc *fakeTSLocalClient, _ *corev1.Secret) {
				lc.networkLockStatus.Enabled = false
			},
			expectedDone:  true,
			expectedError: nil,
			expectedLogs:  []string{"Tailnet is not locked, skipping node key signing"},
		},
		{
			name: "device is visible peer",
			mutationFn: func(lc *fakeTSLocalClient, _ *corev1.Secret) {
				lc.networkLockStatus.VisiblePeers = []*ipnstate.TKAPeer{nodeTkaPeer}
			},
			expectedDone:  true,
			expectedError: nil,
			expectedLogs:  []string{},
		},
		{
			name: "operator key not trusted",
			mutationFn: func(lc *fakeTSLocalClient, _ *corev1.Secret) {
				lc.networkLockStatus.TrustedKeys = nil
			},
			expectedDone:  true,
			expectedError: errOperatorUntrusted,
			expectedLogs: []string{
				fmt.Sprintf("Operator key is not trusted by the network. Add %q to the trusted signer keys", fakeOperatorPublic.CLIString()),
			},
		},
		{
			name: "device not ready",
			mutationFn: func(_ *fakeTSLocalClient, sec *corev1.Secret) {
				delete(sec.Data, kubetypes.KeyDeviceID)
			},
			expectedDone:  false,
			expectedError: nil,
			expectedLogs:  []string{"NodeID is empty. It may not be populated yet"},
		},
		{
			name:          "device not filtered peer",
			mutationFn:    func(_ *fakeTSLocalClient, _ *corev1.Secret) {},
			expectedDone:  false,
			expectedError: nil,
			expectedLogs: []string{
				fmt.Sprintf("Device %q is not found in filtered peers list, deferring signing", nodeId),
			},
		},
		{
			name: "successful signing",
			mutationFn: func(lc *fakeTSLocalClient, _ *corev1.Secret) {
				lc.networkLockStatus.FilteredPeers = []*ipnstate.TKAPeer{nodeTkaPeer}
			},
			expectedDone:  true,
			expectedError: nil,
			expectedLogs: []string{
				fmt.Sprintf("Network is locked. Attempting to sign device node key with operator key %q", fakeOperatorPublic.CLIString()),
			},
		},
		{
			name: "signing error",
			mutationFn: func(lc *fakeTSLocalClient, _ *corev1.Secret) {
				lc.networkLockStatus.FilteredPeers = []*ipnstate.TKAPeer{nodeTkaPeer}
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
					kubetypes.KeyDeviceID: []byte(nodeId),
				},
			}

			lc := newFakeTSLocalClient()
			tt.mutationFn(lc, secret)
			r := &NodeKeySignerReconciler{
				tsLocalClient: lc,
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

func TestNodeKeySignerReconciler_Reconcile(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	lc := newFakeTSLocalClient()
	// Since we're just testing the reconciliation logic, we don't need to
	// enable the network lock.
	lc.networkLockStatus.Enabled = false

	tests := []struct {
		name           string
		mutateFn       func(*corev1.Secret)
		expectedResult reconcile.Result
	}{
		{
			name:           "no error",
			mutateFn:       func(sec *corev1.Secret) {},
			expectedResult: reconcile.Result{},
		},
		{
			name: "missing device id",
			mutateFn: func(sec *corev1.Secret) {
				delete(sec.Data, kubetypes.KeyDeviceID)
			},
			expectedResult: reconcile.Result{RequeueAfter: 5 * time.Second},
		},
		{
			name: "missing secret",
			mutateFn: func(sec *corev1.Secret) {
				// change the name to not match the request
				sec.ObjectMeta.Name = "different-name"
			},
			expectedResult: reconcile.Result{},
		},
		{
			name: "deleting secret",
			mutateFn: func(sec *corev1.Secret) {
				sec.ObjectMeta.DeletionTimestamp = &metav1.Time{
					Time: time.Now(),
				}
				sec.ObjectMeta.Finalizers = []string{"finalizer"}
			},
			expectedResult: reconcile.Result{},
		},
		{
			name: "unmanaged secret",
			mutateFn: func(sec *corev1.Secret) {
				delete(sec.Labels, LabelManaged)
			},
			expectedResult: reconcile.Result{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					Labels: map[string]string{
						LabelManaged: "true",
					},
				},
				Data: map[string][]byte{
					kubetypes.KeyDeviceID: []byte("fake-node-id"),
				},
			}

			request := reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(secret),
			}

			tt.mutateFn(secret)
			fc := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme).
				WithObjects(secret).
				Build()

			r := &NodeKeySignerReconciler{
				Client:        fc,
				logger:        zl.Sugar(),
				tsLocalClient: lc,
			}

			result, err := r.Reconcile(context.TODO(), request)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("unexpected result: %v", result)
			}

		})
	}
}
