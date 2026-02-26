// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailnet_test

import (
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/tailnet"
	"tailscale.com/tstest"
)

func TestReconciler_Reconcile(t *testing.T) {
	t.Parallel()
	clock := tstest.NewClock(tstest.ClockOpts{})
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	tt := []struct {
		Name               string
		Request            reconcile.Request
		Tailnet            *tsapi.Tailnet
		Secret             *corev1.Secret
		ExpectsError       bool
		ExpectedConditions []metav1.Condition
		ClientFunc         func(*tsapi.Tailnet, *corev1.Secret) tailnet.TailscaleClient
	}{
		{
			Name: "ignores unknown tailnet requests",
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: "test",
				},
			},
		},
		{
			Name: "invalid status for missing secret",
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: "test",
				},
			},
			Tailnet: &tsapi.Tailnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: tsapi.TailnetSpec{
					Credentials: tsapi.TailnetCredentials{
						SecretName: "test",
					},
				},
			},
			ExpectedConditions: []metav1.Condition{
				{
					Type:    string(tsapi.TailnetReady),
					Status:  metav1.ConditionFalse,
					Reason:  tailnet.ReasonInvalidSecret,
					Message: `referenced secret "test" does not exist in namespace "tailscale"`,
				},
			},
		},
		{
			Name: "invalid status for empty secret",
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: "test",
				},
			},
			Tailnet: &tsapi.Tailnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: tsapi.TailnetSpec{
					Credentials: tsapi.TailnetCredentials{
						SecretName: "test",
					},
				},
			},
			Secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tailscale",
				},
			},
			ExpectedConditions: []metav1.Condition{
				{
					Type:    string(tsapi.TailnetReady),
					Status:  metav1.ConditionFalse,
					Reason:  tailnet.ReasonInvalidSecret,
					Message: `Secret "test" is empty`,
				},
			},
		},
		{
			Name: "invalid status for missing client id",
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: "test",
				},
			},
			Tailnet: &tsapi.Tailnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: tsapi.TailnetSpec{
					Credentials: tsapi.TailnetCredentials{
						SecretName: "test",
					},
				},
			},
			Secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tailscale",
				},
				Data: map[string][]byte{
					"client_secret": []byte("test"),
				},
			},
			ExpectedConditions: []metav1.Condition{
				{
					Type:    string(tsapi.TailnetReady),
					Status:  metav1.ConditionFalse,
					Reason:  tailnet.ReasonInvalidSecret,
					Message: `Secret "test" is missing the client_id field`,
				},
			},
		},
		{
			Name: "invalid status for missing client secret",
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: "test",
				},
			},
			Tailnet: &tsapi.Tailnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: tsapi.TailnetSpec{
					Credentials: tsapi.TailnetCredentials{
						SecretName: "test",
					},
				},
			},
			Secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tailscale",
				},
				Data: map[string][]byte{
					"client_id": []byte("test"),
				},
			},
			ExpectedConditions: []metav1.Condition{
				{
					Type:    string(tsapi.TailnetReady),
					Status:  metav1.ConditionFalse,
					Reason:  tailnet.ReasonInvalidSecret,
					Message: `Secret "test" is missing the client_secret field`,
				},
			},
		},
		{
			Name: "invalid status for bad devices scope",
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: "test",
				},
			},
			Tailnet: &tsapi.Tailnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: tsapi.TailnetSpec{
					Credentials: tsapi.TailnetCredentials{
						SecretName: "test",
					},
				},
			},
			Secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tailscale",
				},
				Data: map[string][]byte{
					"client_id":     []byte("test"),
					"client_secret": []byte("test"),
				},
			},
			ClientFunc: func(_ *tsapi.Tailnet, _ *corev1.Secret) tailnet.TailscaleClient {
				return &MockTailnetClient{ErrorOnDevices: true}
			},
			ExpectedConditions: []metav1.Condition{
				{
					Type:    string(tsapi.TailnetReady),
					Status:  metav1.ConditionFalse,
					Reason:  tailnet.ReasonInvalidOAuth,
					Message: `failed to list devices: EOF`,
				},
			},
		},
		{
			Name: "invalid status for bad services scope",
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: "test",
				},
			},
			Tailnet: &tsapi.Tailnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: tsapi.TailnetSpec{
					Credentials: tsapi.TailnetCredentials{
						SecretName: "test",
					},
				},
			},
			Secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tailscale",
				},
				Data: map[string][]byte{
					"client_id":     []byte("test"),
					"client_secret": []byte("test"),
				},
			},
			ClientFunc: func(_ *tsapi.Tailnet, _ *corev1.Secret) tailnet.TailscaleClient {
				return &MockTailnetClient{ErrorOnServices: true}
			},
			ExpectedConditions: []metav1.Condition{
				{
					Type:    string(tsapi.TailnetReady),
					Status:  metav1.ConditionFalse,
					Reason:  tailnet.ReasonInvalidOAuth,
					Message: `failed to list tailscale services: EOF`,
				},
			},
		},
		{
			Name: "invalid status for bad keys scope",
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: "test",
				},
			},
			Tailnet: &tsapi.Tailnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: tsapi.TailnetSpec{
					Credentials: tsapi.TailnetCredentials{
						SecretName: "test",
					},
				},
			},
			Secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tailscale",
				},
				Data: map[string][]byte{
					"client_id":     []byte("test"),
					"client_secret": []byte("test"),
				},
			},
			ClientFunc: func(_ *tsapi.Tailnet, _ *corev1.Secret) tailnet.TailscaleClient {
				return &MockTailnetClient{ErrorOnKeys: true}
			},
			ExpectedConditions: []metav1.Condition{
				{
					Type:    string(tsapi.TailnetReady),
					Status:  metav1.ConditionFalse,
					Reason:  tailnet.ReasonInvalidOAuth,
					Message: `failed to list auth keys: EOF`,
				},
			},
		},
		{
			Name: "ready when valid and scopes are correct",
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: "default",
				},
			},
			Tailnet: &tsapi.Tailnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: tsapi.TailnetSpec{
					Credentials: tsapi.TailnetCredentials{
						SecretName: "test",
					},
				},
			},
			Secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tailscale",
				},
				Data: map[string][]byte{
					"client_id":     []byte("test"),
					"client_secret": []byte("test"),
				},
			},
			ClientFunc: func(_ *tsapi.Tailnet, _ *corev1.Secret) tailnet.TailscaleClient {
				return &MockTailnetClient{}
			},
			ExpectedConditions: []metav1.Condition{
				{
					Type:    string(tsapi.TailnetReady),
					Status:  metav1.ConditionTrue,
					Reason:  tailnet.ReasonValid,
					Message: tailnet.ReasonValid,
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(tsapi.GlobalScheme)
			if tc.Tailnet != nil {
				builder = builder.WithObjects(tc.Tailnet).WithStatusSubresource(tc.Tailnet)
			}
			if tc.Secret != nil {
				builder = builder.WithObjects(tc.Secret)
			}

			fc := builder.Build()
			opts := tailnet.ReconcilerOptions{
				Client:             fc,
				Clock:              clock,
				Logger:             logger.Sugar(),
				ClientFunc:         tc.ClientFunc,
				TailscaleNamespace: "tailscale",
			}

			reconciler := tailnet.NewReconciler(opts)
			_, err = reconciler.Reconcile(t.Context(), tc.Request)
			if tc.ExpectsError && err == nil {
				t.Fatalf("expected error, got none")
			}

			if !tc.ExpectsError && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if len(tc.ExpectedConditions) == 0 {
				return
			}

			var tn tsapi.Tailnet
			if err = fc.Get(t.Context(), tc.Request.NamespacedName, &tn); err != nil {
				t.Fatal(err)
			}

			if len(tn.Status.Conditions) != len(tc.ExpectedConditions) {
				t.Fatalf("expected %v condition(s), got %v", len(tc.ExpectedConditions), len(tn.Status.Conditions))
			}

			for i, expected := range tc.ExpectedConditions {
				actual := tn.Status.Conditions[i]

				if actual.Type != expected.Type {
					t.Errorf("expected %v, got %v", expected.Type, actual.Type)
				}

				if actual.Status != expected.Status {
					t.Errorf("expected %v, got %v", expected.Status, actual.Status)
				}

				if actual.Reason != expected.Reason {
					t.Errorf("expected %v, got %v", expected.Reason, actual.Reason)
				}

				if actual.Message != expected.Message {
					t.Errorf("expected %v, got %v", expected.Message, actual.Message)
				}
			}

			if err = fc.Delete(t.Context(), &tn); err != nil {
				t.Fatal(err)
			}

			if _, err = reconciler.Reconcile(t.Context(), tc.Request); err != nil {
				t.Fatal(err)
			}

			err = fc.Get(t.Context(), tc.Request.NamespacedName, &tn)
			if !apierrors.IsNotFound(err) {
				t.Fatalf("expected not found error, got %v", err)
			}
		})
	}
}
