// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

const tsNamespace = "tailscale"

func TestTSRecorder(t *testing.T) {
	tsr := &tsapi.TSRecorder{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Finalizers: []string{"tailscale.com/finalizer"},
		},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(tsr).
		WithStatusSubresource(tsr).
		Build()
	tsClient := &fakeTSClient{}
	zl, _ := zap.NewDevelopment()
	fr := record.NewFakeRecorder(1)
	cl := tstest.NewClock(tstest.ClockOpts{})
	reconciler := &TSRecorderReconciler{
		tsNamespace: tsNamespace,
		Client:      fc,
		tsClient:    tsClient,
		recorder:    fr,
		l:           zl.Sugar(),
		clock:       cl,
	}

	t.Run("invalid spec gives an error condition", func(t *testing.T) {
		expectReconciled(t, reconciler, "", tsr.Name)

		msg := "TSRecorder is invalid: TSRecorder CR test must specify a storage destination for recordings"
		tsoperator.SetTSRecorderCondition(tsr, tsapi.TSRecorderReady, metav1.ConditionFalse, reasonTSRecorderInvalid, msg, 0, cl, zl.Sugar())
		expectEqual(t, fc, tsr, nil)
		if expected := 0; reconciler.tsRecorders.Len() != expected {
			t.Fatalf("expected %d recorders, got %d", expected, reconciler.tsRecorders.Len())
		}
		expectTSRecorderResources(t, fc, tsr, false)

		expectedEvent := "Warning TSRecorderInvalid TSRecorder is invalid: TSRecorder CR test must specify a storage destination for recordings"
		expectEvents(t, fr, []string{expectedEvent})
	})

	t.Run("observe Ready=true status condition for a valid spec", func(t *testing.T) {
		tsr.Spec.Storage.File.Directory = "storage-directory"
		mustUpdate(t, fc, "", "test", func(t *tsapi.TSRecorder) {
			t.Spec = tsr.Spec
		})

		expectReconciled(t, reconciler, "", tsr.Name)

		tsoperator.SetTSRecorderCondition(tsr, tsapi.TSRecorderReady, metav1.ConditionTrue, reasonTSRecorderCreated, reasonTSRecorderCreated, 0, cl, zl.Sugar())
		expectEqual(t, fc, tsr, nil)
		if expected := 1; reconciler.tsRecorders.Len() != expected {
			t.Fatalf("expected %d recorders, got %d", expected, reconciler.tsRecorders.Len())
		}
		expectTSRecorderResources(t, fc, tsr, true)
	})

	t.Run("populate node info in state secret, and see it appear in status", func(t *testing.T) {
		bytes, err := json.Marshal(map[string]any{
			"Config": map[string]any{
				"NodeID": "nodeid-123",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		const key = "profile-abc"
		mustUpdate(t, fc, tsNamespace, "test-0", func(s *corev1.Secret) {
			s.Data = map[string][]byte{
				currentProfileKey: []byte(key),
				key:               bytes,
			}
		})

		expectReconciled(t, reconciler, "", tsr.Name)
		tsr.Status.Devices = []tsapi.TailnetDevice{
			{
				Hostname:   "test-device",
				TailnetIPs: []string{"1.2.3.4", "::1"},
			},
		}
		expectEqual(t, fc, tsr, nil)
	})

	t.Run("delete the TSRecorder and observe cleanup", func(t *testing.T) {
		if err := fc.Delete(context.Background(), tsr); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", tsr.Name)

		expectMissing[tsapi.TSRecorder](t, fc, "", tsr.Name)
		if expected := 0; reconciler.tsRecorders.Len() != expected {
			t.Fatalf("expected %d recorders, got %d", expected, reconciler.tsRecorders.Len())
		}
		if diff := cmp.Diff(tsClient.deleted, []string{"nodeid-123"}); diff != "" {
			t.Fatalf("unexpected deleted devices (-got +want):\n%s", diff)
		}
		// The fake client does not clean up objects whose owner has been
		// deleted, so we can't test for the owned resources getting deleted.
	})
}

func expectTSRecorderResources(t *testing.T, fc client.WithWatch, tsr *tsapi.TSRecorder, shouldExist bool) {
	t.Helper()

	auth := tsrAuthSecret(tsr, tsNamespace, "secret-authkey")
	state := tsrStateSecret(tsr, tsNamespace)
	role := tsrRole(tsr, tsNamespace)
	roleBinding := tsrRoleBinding(tsr, tsNamespace)
	serviceAccount := tsrServiceAccount(tsr, tsNamespace)
	statefulSet := tsrStatefulSet(tsr, tsNamespace)

	if shouldExist {
		expectEqual(t, fc, auth, nil)
		expectEqual(t, fc, state, nil)
		expectEqual(t, fc, role, nil)
		expectEqual(t, fc, roleBinding, nil)
		expectEqual(t, fc, serviceAccount, nil)
		expectEqual(t, fc, statefulSet, nil)
	} else {
		expectMissing[corev1.Secret](t, fc, auth.Namespace, auth.Name)
		expectMissing[corev1.Secret](t, fc, state.Namespace, state.Name)
		expectMissing[rbacv1.Role](t, fc, role.Namespace, role.Name)
		expectMissing[rbacv1.RoleBinding](t, fc, roleBinding.Namespace, roleBinding.Name)
		expectMissing[corev1.ServiceAccount](t, fc, serviceAccount.Namespace, serviceAccount.Name)
		expectMissing[appsv1.StatefulSet](t, fc, statefulSet.Namespace, statefulSet.Name)
	}
}
