// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package nodekey_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/nodekey"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

var _ nodekey.LocalClient = (*local.Client)(nil)

var _ nodekey.LocalClient = (*fakeLocalClient)(nil)

// fakeLocalClient is a nodekey.LocalClient. By default it reports Tailnet Lock as
// disabled, so Reconcile can be exercised without performing any signing. It
// records whether the lock status was queried, which shows whether a Secret
// made it past Reconcile's filtering, and the arguments of any signing call.
// Set lockStatus to simulate a locked tailnet.
type fakeLocalClient struct {
	lockStatus   *ipnstate.TailnetLockStatus
	statusErr    error
	statusCalled bool

	signErr        error
	signCalled     bool
	signedKey      key.NodePublic
	signedRotation []byte
}

func (c *fakeLocalClient) TailnetLockSign(_ context.Context, nodeKey key.NodePublic, rotationPublic []byte) error {
	c.signCalled = true
	c.signedKey = nodeKey
	c.signedRotation = rotationPublic
	return c.signErr
}

func (c *fakeLocalClient) TailnetLockStatus(context.Context) (*ipnstate.TailnetLockStatus, error) {
	c.statusCalled = true
	if c.statusErr != nil {
		return nil, c.statusErr
	}
	if c.lockStatus == nil {
		return &ipnstate.TailnetLockStatus{Enabled: false}, nil
	}
	return c.lockStatus, nil
}

// lockedStatus returns the status of a locked tailnet in which the operator's key is trusted and the device with the
// given ID and node key is awaiting a signature.
func lockedStatus(deviceID tailcfg.StableNodeID, nodeKey key.NodePublic) *ipnstate.TailnetLockStatus {
	operatorKey := key.NewTLPrivate().Public()
	return &ipnstate.TailnetLockStatus{
		Enabled:     true,
		PublicKey:   operatorKey,
		TrustedKeys: []ipnstate.TKAKey{{Key: operatorKey}},
		FilteredPeers: []*ipnstate.TKAPeer{
			{StableID: deviceID, NodeKey: nodeKey},
		},
	}
}

func TestReconciler_Reconcile(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	const (
		deviceID tailcfg.StableNodeID = "fake-node-id"

		profileKey = "profile-test"
	)

	nodePrivate := key.NewNode()
	nodeKey := nodePrivate.Public()

	// profile returns an IPN profile as tailscaled writes it to the state Secret.
	profile := func(p *persist.Persist) []byte {
		b, err := json.Marshal(ipn.Prefs{Persist: p})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	tests := []struct {
		name           string
		mutateFn       func(*corev1.Secret, *fakeLocalClient)
		expectedResult reconcile.Result
		expectedLookup bool // whether the Secret is expected to reach the Tailnet Lock status lookup
		expectedSign   bool
		wantErr        bool
	}{
		{
			name:           "unlocked",
			mutateFn:       func(sec *corev1.Secret, _ *fakeLocalClient) {},
			expectedResult: reconcile.Result{},
			expectedLookup: true,
		},
		{
			name: "lock_status_error",
			mutateFn: func(_ *corev1.Secret, lc *fakeLocalClient) {
				lc.statusErr = errors.New("status unavailable")
			},
			expectedResult: reconcile.Result{},
			expectedLookup: true,
			wantErr:        true,
		},
		{
			name: "missing_device_id",
			mutateFn: func(sec *corev1.Secret, _ *fakeLocalClient) {
				delete(sec.Data, kubetypes.KeyDeviceID)
			},
			expectedResult: reconcile.Result{},
		},
		{
			name: "missing_secret",
			mutateFn: func(sec *corev1.Secret, _ *fakeLocalClient) {
				// change the name to not match the request
				sec.ObjectMeta.Name = "different-name"
			},
			expectedResult: reconcile.Result{},
		},
		{
			name: "deleting_secret",
			mutateFn: func(sec *corev1.Secret, _ *fakeLocalClient) {
				sec.ObjectMeta.DeletionTimestamp = &metav1.Time{
					Time: time.Now(),
				}
				sec.ObjectMeta.Finalizers = []string{"finalizer"}
			},
			expectedResult: reconcile.Result{},
		},
		{
			name: "locked_signed",
			mutateFn: func(_ *corev1.Secret, lc *fakeLocalClient) {
				lc.lockStatus = lockedStatus(deviceID, nodeKey)
			},
			expectedResult: reconcile.Result{},
			expectedLookup: true,
			expectedSign:   true,
		},
		{
			name: "locked_sign_error",
			mutateFn: func(_ *corev1.Secret, lc *fakeLocalClient) {
				lc.lockStatus = lockedStatus(deviceID, nodeKey)
				lc.signErr = errors.New("signing failed")
			},
			// Errors are returned so controller-runtime retries with backoff.
			expectedResult: reconcile.Result{},
			expectedLookup: true,
			expectedSign:   true,
			wantErr:        true,
		},
		{
			name: "locked_operator_untrusted",
			mutateFn: func(_ *corev1.Secret, lc *fakeLocalClient) {
				lc.lockStatus = lockedStatus(deviceID, nodeKey)
				lc.lockStatus.TrustedKeys = nil
			},
			// Not an error: the user needs to trust the operator's key, so check back slowly.
			expectedResult: reconcile.Result{RequeueAfter: 60 * time.Second},
			expectedLookup: true,
		},
		{
			name: "locked_device_not_filtered_peer",
			mutateFn: func(_ *corev1.Secret, lc *fakeLocalClient) {
				lc.lockStatus = lockedStatus(deviceID, nodeKey)
				lc.lockStatus.FilteredPeers = nil
			},
			// Control may not have propagated the device yet, and that does not trigger a Secret event.
			expectedResult: reconcile.Result{RequeueAfter: 60 * time.Second},
			expectedLookup: true,
		},
		{
			name: "locked_device_visible_peer",
			mutateFn: func(_ *corev1.Secret, lc *fakeLocalClient) {
				lc.lockStatus = lockedStatus(deviceID, nodeKey)
				lc.lockStatus.VisiblePeers, lc.lockStatus.FilteredPeers = lc.lockStatus.FilteredPeers, nil
			},
			expectedResult: reconcile.Result{},
			expectedLookup: true,
		},
		{
			name: "locked_visible_peer_key_mismatch",
			mutateFn: func(_ *corev1.Secret, lc *fakeLocalClient) {
				lc.lockStatus = lockedStatus(deviceID, key.NewNode().Public())
				lc.lockStatus.VisiblePeers, lc.lockStatus.FilteredPeers = lc.lockStatus.FilteredPeers, nil
			},
			// Control still shows the device's previous, signed key; retry until the netmap catches up.
			expectedResult: reconcile.Result{RequeueAfter: 60 * time.Second},
			expectedLookup: true,
		},
		{
			name: "missing_profile",
			mutateFn: func(sec *corev1.Secret, lc *fakeLocalClient) {
				delete(sec.Data, string(ipn.CurrentProfileStateKey))
				lc.lockStatus = lockedStatus(deviceID, nodeKey)
			},
			// No requeue: tailscaled writing its profile triggers a new reconcile via the Secret watch.
			expectedResult: reconcile.Result{},
		},
		{
			name: "profile_without_persist",
			mutateFn: func(sec *corev1.Secret, lc *fakeLocalClient) {
				sec.Data[profileKey] = profile(nil)
				lc.lockStatus = lockedStatus(deviceID, nodeKey)
			},
			expectedResult: reconcile.Result{},
		},
		{
			name: "profile_without_node_key",
			mutateFn: func(sec *corev1.Secret, lc *fakeLocalClient) {
				sec.Data[profileKey] = profile(&persist.Persist{})
				lc.lockStatus = lockedStatus(deviceID, nodeKey)
			},
			expectedResult: reconcile.Result{},
		},
		{
			name: "malformed_profile",
			mutateFn: func(sec *corev1.Secret, lc *fakeLocalClient) {
				sec.Data[profileKey] = []byte("not-a-profile")
				lc.lockStatus = lockedStatus(deviceID, nodeKey)
			},
			expectedResult: reconcile.Result{},
			wantErr:        true,
		},
		{
			name: "locked_node_key_mismatch",
			mutateFn: func(sec *corev1.Secret, lc *fakeLocalClient) {
				sec.Data[profileKey] = profile(&persist.Persist{PrivateNodeKey: key.NewNode()})
				lc.lockStatus = lockedStatus(deviceID, nodeKey)
			},
			// Keys can briefly disagree during rotation, so retry rather than error.
			expectedResult: reconcile.Result{RequeueAfter: 60 * time.Second},
			expectedLookup: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					Labels: map[string]string{
						kubetypes.LabelManaged: "true",
					},
				},
				Data: map[string][]byte{
					kubetypes.KeyDeviceID:              []byte(deviceID),
					string(ipn.CurrentProfileStateKey): []byte(profileKey),
					profileKey:                         profile(&persist.Persist{PrivateNodeKey: nodePrivate}),
				},
			}

			request := reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(secret),
			}

			lc := &fakeLocalClient{}

			tt.mutateFn(secret, lc)
			fc := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme).
				WithObjects(secret).
				Build()

			r := nodekey.NewReconciler(nodekey.ReconcilerOptions{
				Client:             fc,
				TailscaleNamespace: "test-namespace",
				LocalClient:        lc,
				Logger:             zl.Sugar(),
			})

			result, err := r.Reconcile(t.Context(), request)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("unexpected result: %v", result)
			}
			if lc.statusCalled != tt.expectedLookup {
				t.Errorf("tailnet lock status lookup = %v, want %v", lc.statusCalled, tt.expectedLookup)
			}
			if lc.signCalled != tt.expectedSign {
				t.Errorf("sign called = %v, want %v", lc.signCalled, tt.expectedSign)
			}
			if tt.expectedSign {
				// The key signed must be the one the device reported, and no rotation key is set on its behalf.
				if lc.signedKey != nodeKey {
					t.Errorf("signed key = %v, want %v", lc.signedKey, nodeKey)
				}
				if lc.signedRotation != nil {
					t.Errorf("signed with rotation key %x, want nil", lc.signedRotation)
				}
			}
		})
	}
}
