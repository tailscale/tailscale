// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package nodekey_test

import (
	"context"
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
	"tailscale.com/ipn/ipnstate"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/nodekey"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/key"
)

var _ nodekey.LocalClient = (*local.Client)(nil)

var _ nodekey.LocalClient = (*unlockedLocalClient)(nil)

// unlockedLocalClient is a nodekey.LocalClient that reports Tailnet Lock as
// disabled, so Reconcile can be exercised without performing any signing.
type unlockedLocalClient struct{}

func (unlockedLocalClient) NetworkLockSign(context.Context, key.NodePublic, []byte) error {
	return nil
}

func (unlockedLocalClient) NetworkLockStatus(context.Context) (*ipnstate.TailnetLockStatus, error) {
	return &ipnstate.TailnetLockStatus{Enabled: false}, nil
}

func TestReconciler_Reconcile(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		mutateFn       func(*corev1.Secret)
		expectedResult reconcile.Result
	}{
		{
			name:           "no_error",
			mutateFn:       func(sec *corev1.Secret) {},
			expectedResult: reconcile.Result{},
		},
		{
			name: "missing_device_id",
			mutateFn: func(sec *corev1.Secret) {
				delete(sec.Data, kubetypes.KeyDeviceID)
			},
			expectedResult: reconcile.Result{RequeueAfter: 5 * time.Second},
		},
		{
			name: "missing_secret",
			mutateFn: func(sec *corev1.Secret) {
				// change the name to not match the request
				sec.ObjectMeta.Name = "different-name"
			},
			expectedResult: reconcile.Result{},
		},
		{
			name: "deleting_secret",
			mutateFn: func(sec *corev1.Secret) {
				sec.ObjectMeta.DeletionTimestamp = &metav1.Time{
					Time: time.Now(),
				}
				sec.ObjectMeta.Finalizers = []string{"finalizer"}
			},
			expectedResult: reconcile.Result{},
		},
		{
			name: "unmanaged_secret",
			mutateFn: func(sec *corev1.Secret) {
				delete(sec.Labels, kubetypes.LabelManaged)
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
						kubetypes.LabelManaged: "true",
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

			r := nodekey.NewReconciler(nodekey.ReconcilerOptions{
				Client:             fc,
				TailscaleNamespace: "test-namespace",
				LocalClient:        unlockedLocalClient{},
				Logger:             zl.Sugar(),
			})

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
