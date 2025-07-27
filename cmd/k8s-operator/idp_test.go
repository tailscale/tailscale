// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstime"
)

func TestIDPReconciler_BasicFlow(t *testing.T) {
	// Test basic creation flow similar to Recorder
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&tsapi.IDP{}).
		Build()

	idp := &tsapi.IDP{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-idp",
			Namespace: "default",
		},
		Spec: tsapi.IDPSpec{
			Hostname: "idp-test",
			Tags:     tsapi.Tags{"tag:k8s"},
		},
	}

	r := &IDPReconciler{
		Client:      fc,
		l:           zap.L().Sugar(),
		recorder:    record.NewFakeRecorder(100),
		tsNamespace: "tailscale",
		clock:       tstime.DefaultClock{},
		tsClient:    &fakeTSClient{},
	}

	if err := fc.Create(context.Background(), idp); err != nil {
		t.Fatalf("failed to create IDP: %v", err)
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-idp",
			Namespace: "default",
		},
	}

	_, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconciliation failed: %v", err)
	}

	// Verify resources were created
	verifyResourcesCreated(t, fc, "test-idp", "tailscale")
}

func TestTSIDPEnv(t *testing.T) {
	tests := []struct {
		name    string
		idp     *tsapi.IDP
		wantEnv map[string]string
	}{
		{
			name: "basic",
			idp: &tsapi.IDP{
				ObjectMeta: metav1.ObjectMeta{Name: "test-idp"},
				Spec: tsapi.IDPSpec{
					Hostname: "idp-test",
					Port:     443,
				},
			},
			wantEnv: map[string]string{
				"TS_STATE":                   "kube:test-idp-state",
				"TSIDP_VERBOSE":              "true",
				"TS_HOSTNAME":                "idp-test",
				"TSIDP_PORT":                 "443",
				"TSIDP_FUNNEL_CLIENTS_STORE": "kube:test-idp-funnel-clients",
			},
		},
		{
			name: "with-funnel-and-local-port",
			idp: &tsapi.IDP{
				ObjectMeta: metav1.ObjectMeta{Name: "test-idp"},
				Spec: tsapi.IDPSpec{
					Hostname:     "idp-mcp",
					Port:         8443,
					EnableFunnel: true,
					LocalPort:    &[]int32{9080}[0],
				},
			},
			wantEnv: map[string]string{
				"TS_STATE":                   "kube:test-idp-state",
				"TSIDP_VERBOSE":              "true",
				"TS_HOSTNAME":                "idp-mcp",
				"TSIDP_PORT":                 "8443",
				"TSIDP_FUNNEL":               "true",
				"TSIDP_LOCAL_PORT":           "9080",
				"TSIDP_FUNNEL_CLIENTS_STORE": "kube:test-idp-funnel-clients",
			},
		},
		{
			name: "with-custom-env",
			idp: &tsapi.IDP{
				ObjectMeta: metav1.ObjectMeta{Name: "test-idp"},
				Spec: tsapi.IDPSpec{
					Hostname:     "idp-mcp",
					Port:         8443,
					EnableFunnel: true,
					StatefulSet: tsapi.IDPStatefulSet{
						Pod: tsapi.IDPPod{
							Container: tsapi.IDPContainer{
								Env: []tsapi.Env{
									{Name: tsapi.Name("CUSTOM_VAR"), Value: "custom-value"},
								},
							},
						},
					},
				},
			},
			wantEnv: map[string]string{
				"TS_STATE":                   "kube:test-idp-state",
				"TSIDP_VERBOSE":              "true",
				"TS_HOSTNAME":                "idp-mcp",
				"TSIDP_PORT":                 "8443",
				"TSIDP_FUNNEL":               "true",
				"TSIDP_FUNNEL_CLIENTS_STORE": "kube:test-idp-funnel-clients",
				"CUSTOM_VAR":                 "custom-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := idpEnv(tt.idp, "")

			envMap := make(map[string]string)
			for _, e := range env {
				if e.Value != "" {
					envMap[e.Name] = e.Value
				}
			}

			for key, expected := range tt.wantEnv {
				if got, exists := envMap[key]; !exists {
					t.Errorf("expected env var %s not found", key)
				} else if got != expected {
					t.Errorf("env var %s: expected %q, got %q", key, expected, got)
				}
			}

			var hasAuthKey bool
			for _, e := range env {
				if e.Name == "TS_AUTHKEY" && e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
					hasAuthKey = true
					break
				}
			}
			if !hasAuthKey {
				t.Error("expected TS_AUTHKEY to be set via secret reference")
			}
		})
	}
}

func TestIDPStatusConditions(t *testing.T) {
	// Test that invalid specs produce proper status conditions
	idp := &tsapi.IDP{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-idp",
			Namespace:  "default",
			Finalizers: []string{FinalizerName},
		},
		Spec: tsapi.IDPSpec{
			Tags: tsapi.Tags{"invalid-tag"}, // Missing tag: prefix
		},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(idp).
		WithStatusSubresource(idp).
		Build()

	fr := record.NewFakeRecorder(10)

	r := &IDPReconciler{
		Client:      fc,
		l:           zap.L().Sugar(),
		recorder:    fr,
		tsNamespace: "tailscale",
		clock:       tstime.DefaultClock{},
		tsClient:    &fakeTSClient{},
	}

	expectReconciled(t, r, idp.Namespace, idp.Name)

	updatedIDP := &tsapi.IDP{}
	if err := fc.Get(context.Background(), client.ObjectKey{Name: idp.Name, Namespace: idp.Namespace}, updatedIDP); err != nil {
		t.Fatal(err)
	}

	if len(updatedIDP.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(updatedIDP.Status.Conditions))
	}

	cond := updatedIDP.Status.Conditions[0]
	if cond.Type != string(tsapi.IDPReady) || cond.Status != metav1.ConditionFalse || cond.Reason != reasonIDPInvalid {
		t.Fatalf("expected condition IDPReady false with reason IDPInvalid, got %v", cond)
	}

	if !strings.Contains(cond.Message, "must start with 'tag:'") {
		t.Errorf("expected validation error in condition message, got %q", cond.Message)
	}

	select {
	case event := <-fr.Events:
		if !strings.Contains(event, "IDPInvalid") {
			t.Errorf("expected IDPInvalid event, got %q", event)
		}
	default:
		t.Error("expected event to be recorded")
	}
}

func TestIDPValidation(t *testing.T) {
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		Build()

	r := &IDPReconciler{
		Client:      fc,
		l:           zap.L().Sugar(),
		recorder:    record.NewFakeRecorder(100),
		tsNamespace: "tailscale",
	}

	tests := []struct {
		name    string
		idp     *tsapi.IDP
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid",
			idp: &tsapi.IDP{
				Spec: tsapi.IDPSpec{
					Hostname: "idp-test",
					Tags:     tsapi.Tags{"tag:k8s", "tag:mcp"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid-tag-missing-prefix",
			idp: &tsapi.IDP{
				Spec: tsapi.IDPSpec{
					Hostname: "idp-test",
					Tags:     tsapi.Tags{"invalid-tag"},
				},
			},
			wantErr: true,
			errMsg:  "must start with 'tag:'",
		},
		{
			name: "invalid-tag-empty-name",
			idp: &tsapi.IDP{
				Spec: tsapi.IDPSpec{
					Hostname: "idp-test",
					Tags:     tsapi.Tags{"tag:"},
				},
			},
			wantErr: true,
			errMsg:  "tag names must not be empty",
		},
		{
			name: "invalid-tag-special-chars",
			idp: &tsapi.IDP{
				Spec: tsapi.IDPSpec{
					Hostname: "idp-test",
					Tags:     tsapi.Tags{"tag:test@123"},
				},
			},
			wantErr: true,
			errMsg:  "tag names can only contain numbers, letters, or dashes",
		},
		{
			name: "hostname-too-long",
			idp: &tsapi.IDP{
				Spec: tsapi.IDPSpec{
					Hostname: "this-hostname-is-way-too-long-and-exceeds-the-63-character-limit-for-dns-names",
				},
			},
			wantErr: true,
			errMsg:  "must be 63 characters or less",
		},
		{
			name: "hostname-invalid-chars",
			idp: &tsapi.IDP{
				Spec: tsapi.IDPSpec{
					Hostname: "idp_test",
				},
			},
			wantErr: true,
			errMsg:  "must be a valid DNS label",
		},
		{
			name: "hostname-starts-with-dash",
			idp: &tsapi.IDP{
				Spec: tsapi.IDPSpec{
					Hostname: "-idp-test",
				},
			},
			wantErr: true,
			errMsg:  "must be a valid DNS label",
		},
		{
			name: "invalid-port-zero",
			idp: &tsapi.IDP{
				Spec: tsapi.IDPSpec{
					Hostname: "idp-test",
					Port:     0,
				},
			},
			wantErr: false, // Port 0 means default (443)
		},
		{
			name: "invalid-port-too-high",
			idp: &tsapi.IDP{
				Spec: tsapi.IDPSpec{
					Hostname: "idp-test",
					Port:     65536,
				},
			},
			wantErr: true,
			errMsg:  "out of valid range",
		},
		{
			name: "funnel-with-non-443-port",
			idp: &tsapi.IDP{
				Spec: tsapi.IDPSpec{
					Hostname:     "idp-test",
					EnableFunnel: true,
					Port:         8443,
				},
			},
			wantErr: true,
			errMsg:  "port must be 443 or unset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.validate(context.Background(), tt.idp)
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("validate() error = %v, expected to contain %q", err, tt.errMsg)
			}
		})
	}
}

func TestIDPServiceAccountHandling(t *testing.T) {
	// Test custom ServiceAccount name works
	t.Run("custom_service_account_name", func(t *testing.T) {
		idp := &tsapi.IDP{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-idp",
				Namespace: "default",
			},
			Spec: tsapi.IDPSpec{
				Hostname: "idp-test",
				StatefulSet: tsapi.IDPStatefulSet{
					Pod: tsapi.IDPPod{
						ServiceAccount: tsapi.IDPServiceAccount{
							Name: "custom-sa",
						},
					},
				},
			},
		}

		fc := fake.NewClientBuilder().
			WithScheme(tsapi.GlobalScheme).
			WithStatusSubresource(&tsapi.IDP{}).
			Build()

		r := &IDPReconciler{
			Client:      fc,
			l:           zap.L().Sugar(),
			recorder:    record.NewFakeRecorder(100),
			tsNamespace: "tailscale",
			clock:       tstime.DefaultClock{},
			tsClient:    &fakeTSClient{},
		}

		if err := fc.Create(context.Background(), idp); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, r, idp.Namespace, idp.Name)

		// Verify custom ServiceAccount was created
		sa := &corev1.ServiceAccount{}
		if err := fc.Get(context.Background(), types.NamespacedName{
			Name:      "custom-sa",
			Namespace: "tailscale",
		}, sa); err != nil {
			t.Errorf("expected custom ServiceAccount to be created: %v", err)
		}
	})

	// Test ServiceAccount conflict detection
	t.Run("service_account_conflict", func(t *testing.T) {
		existingSA := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-sa",
				Namespace: "tailscale",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "v1",
						Kind:       "Pod",
						Name:       "other-pod",
						UID:        "12345",
					},
				},
			},
		}

		idp := &tsapi.IDP{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-idp",
				Namespace: "default",
			},
			Spec: tsapi.IDPSpec{
				Hostname: "idp-test",
				StatefulSet: tsapi.IDPStatefulSet{
					Pod: tsapi.IDPPod{
						ServiceAccount: tsapi.IDPServiceAccount{
							Name: "existing-sa",
						},
					},
				},
			},
		}

		fc := fake.NewClientBuilder().
			WithScheme(tsapi.GlobalScheme).
			WithStatusSubresource(&tsapi.IDP{}).
			WithObjects(existingSA).
			Build()

		r := &IDPReconciler{
			Client:      fc,
			l:           zap.L().Sugar(),
			recorder:    record.NewFakeRecorder(100),
			tsNamespace: "tailscale",
			clock:       tstime.DefaultClock{},
			tsClient:    &fakeTSClient{},
		}

		if err := fc.Create(context.Background(), idp); err != nil {
			t.Fatal(err)
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      idp.Name,
				Namespace: idp.Namespace,
			},
		}

		_, err := r.Reconcile(context.Background(), req)
		if err == nil {
			t.Error("expected error for ServiceAccount conflict")
		}
	})
}

func TestIDPDeletion(t *testing.T) {
	// Test deletion flow - similar to Recorder
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&tsapi.IDP{}).
		Build()

	idp := &tsapi.IDP{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-idp",
			Namespace:  "default",
			Finalizers: []string{FinalizerName},
		},
		Spec: tsapi.IDPSpec{
			Hostname: "idp-test",
		},
	}

	r := &IDPReconciler{
		Client:      fc,
		l:           zap.L().Sugar(),
		recorder:    record.NewFakeRecorder(100),
		tsNamespace: "tailscale",
		clock:       tstime.DefaultClock{},
		tsClient:    &fakeTSClient{},
	}

	if err := fc.Create(context.Background(), idp); err != nil {
		t.Fatal(err)
	}

	// Create resources
	expectReconciled(t, r, idp.Namespace, idp.Name)

	// Delete IDP
	if err := fc.Delete(context.Background(), idp); err != nil {
		t.Fatal(err)
	}

	// Reconcile deletion
	expectReconciled(t, r, idp.Namespace, idp.Name)
}

func verifyResourcesCreated(t *testing.T, fc client.Client, name, namespace string) {
	t.Helper()

	sa := &corev1.ServiceAccount{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, sa); err != nil {
		t.Errorf("expected ServiceAccount to be created: %v", err)
	}

	role := &rbacv1.Role{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, role); err != nil {
		t.Errorf("expected Role to be created: %v", err)
	}

	rb := &rbacv1.RoleBinding{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, rb); err != nil {
		t.Errorf("expected RoleBinding to be created: %v", err)
	}

	sts := &appsv1.StatefulSet{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, sts); err != nil {
		t.Errorf("expected StatefulSet to be created: %v", err)
	}

	svc := &corev1.Service{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, svc); err != nil {
		t.Errorf("expected Service to be created: %v", err)
	}

	authSecret := &corev1.Secret{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, authSecret); err != nil {
		t.Errorf("expected auth Secret to be created: %v", err)
	}

	funnelSecret := &corev1.Secret{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      name + "-funnel-clients",
		Namespace: namespace,
	}, funnelSecret); err != nil {
		t.Errorf("expected funnel clients Secret to be created: %v", err)
	} else {
		if data, ok := funnelSecret.Data["funnel-clients"]; !ok {
			t.Error("expected funnel-clients data key in secret")
		} else if string(data) != "{}" {
			t.Errorf("expected funnel-clients data to be '{}', got '%s'", string(data))
		}
	}
}
