// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	"tailscale.com/types/ptr"
)

const (
	tsNamespace   = "tailscale"
	tsLoginServer = "example.tailscale.com"
)

func TestRecorder(t *testing.T) {
	tsr := &tsapi.Recorder{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Finalizers: []string{"tailscale.com/finalizer"},
		},
		Spec: tsapi.RecorderSpec{
			Replicas: ptr.To[int32](3),
		},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(tsr).
		WithStatusSubresource(tsr).
		Build()
	tsClient := &fakeTSClient{}
	zl, _ := zap.NewDevelopment()
	fr := record.NewFakeRecorder(2)
	cl := tstest.NewClock(tstest.ClockOpts{})
	reconciler := &RecorderReconciler{
		tsNamespace: tsNamespace,
		Client:      fc,
		tsClient:    tsClient,
		recorder:    fr,
		log:         zl.Sugar(),
		clock:       cl,
		loginServer: tsLoginServer,
	}

	t.Run("invalid_spec_gives_an_error_condition", func(t *testing.T) {
		expectReconciled(t, reconciler, "", tsr.Name)

		msg := "Recorder is invalid: must either enable UI or use S3 storage to ensure recordings are accessible"
		tsoperator.SetRecorderCondition(tsr, tsapi.RecorderReady, metav1.ConditionFalse, reasonRecorderInvalid, msg, 0, cl, zl.Sugar())
		expectEqual(t, fc, tsr)
		if expected := 0; reconciler.recorders.Len() != expected {
			t.Fatalf("expected %d recorders, got %d", expected, reconciler.recorders.Len())
		}
		expectRecorderResources(t, fc, tsr, false)

		expectedEvent := "Warning RecorderInvalid Recorder is invalid: must either enable UI or use S3 storage to ensure recordings are accessible"
		expectEvents(t, fr, []string{expectedEvent})

		tsr.Spec.EnableUI = true
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations = map[string]string{
			"invalid space characters": "test",
		}
		mustUpdate(t, fc, "", "test", func(t *tsapi.Recorder) {
			t.Spec = tsr.Spec
		})
		expectReconciled(t, reconciler, "", tsr.Name)

		expectedEvent = "Warning RecorderInvalid Recorder is invalid: must use S3 storage when using multiple replicas to ensure recordings are accessible"
		expectEvents(t, fr, []string{expectedEvent})

		tsr.Spec.Storage.S3 = &tsapi.S3{}
		mustUpdate(t, fc, "", "test", func(t *tsapi.Recorder) {
			t.Spec = tsr.Spec
		})
		expectReconciled(t, reconciler, "", tsr.Name)

		// Only check part of this error message, because it's defined in an
		// external package and may change.
		if err := fc.Get(context.Background(), client.ObjectKey{
			Name: tsr.Name,
		}, tsr); err != nil {
			t.Fatal(err)
		}
		if len(tsr.Status.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(tsr.Status.Conditions))
		}
		cond := tsr.Status.Conditions[0]
		if cond.Type != string(tsapi.RecorderReady) || cond.Status != metav1.ConditionFalse || cond.Reason != reasonRecorderInvalid {
			t.Fatalf("expected condition RecorderReady false due to RecorderInvalid, got %v", cond)
		}
		for _, msg := range []string{cond.Message, <-fr.Events} {
			if !strings.Contains(msg, `"invalid space characters"`) {
				t.Fatalf("expected invalid annotation key in error message, got %q", cond.Message)
			}
		}
	})

	t.Run("conflicting_service_account_config_marked_as_invalid", func(t *testing.T) {
		mustCreate(t, fc, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pre-existing-sa",
				Namespace: tsNamespace,
			},
		})

		tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations = nil
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Name = "pre-existing-sa"
		mustUpdate(t, fc, "", "test", func(t *tsapi.Recorder) {
			t.Spec = tsr.Spec
		})

		expectReconciled(t, reconciler, "", tsr.Name)

		msg := `Recorder is invalid: custom ServiceAccount name "pre-existing-sa" specified but conflicts with a pre-existing ServiceAccount in the tailscale namespace`
		tsoperator.SetRecorderCondition(tsr, tsapi.RecorderReady, metav1.ConditionFalse, reasonRecorderInvalid, msg, 0, cl, zl.Sugar())
		expectEqual(t, fc, tsr)
		if expected := 0; reconciler.recorders.Len() != expected {
			t.Fatalf("expected %d recorders, got %d", expected, reconciler.recorders.Len())
		}

		expectedEvent := "Warning RecorderInvalid " + msg
		expectEvents(t, fr, []string{expectedEvent})
	})

	t.Run("observe_Ready_true_status_condition_for_a_valid_spec", func(t *testing.T) {
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Name = ""
		mustUpdate(t, fc, "", "test", func(t *tsapi.Recorder) {
			t.Spec = tsr.Spec
		})

		expectReconciled(t, reconciler, "", tsr.Name)

		tsoperator.SetRecorderCondition(tsr, tsapi.RecorderReady, metav1.ConditionTrue, reasonRecorderCreated, reasonRecorderCreated, 0, cl, zl.Sugar())
		expectEqual(t, fc, tsr)
		if expected := 1; reconciler.recorders.Len() != expected {
			t.Fatalf("expected %d recorders, got %d", expected, reconciler.recorders.Len())
		}
		expectRecorderResources(t, fc, tsr, true)
	})

	t.Run("valid_service_account_config", func(t *testing.T) {
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Name = "test-sa"
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations = map[string]string{
			"test": "test",
		}
		mustUpdate(t, fc, "", "test", func(t *tsapi.Recorder) {
			t.Spec = tsr.Spec
		})

		expectReconciled(t, reconciler, "", tsr.Name)

		expectEqual(t, fc, tsr)
		if expected := 1; reconciler.recorders.Len() != expected {
			t.Fatalf("expected %d recorders, got %d", expected, reconciler.recorders.Len())
		}
		expectRecorderResources(t, fc, tsr, true)

		// Get the service account and check the annotations.
		sa := &corev1.ServiceAccount{}
		if err := fc.Get(context.Background(), client.ObjectKey{
			Name:      tsr.Spec.StatefulSet.Pod.ServiceAccount.Name,
			Namespace: tsNamespace,
		}, sa); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(sa.Annotations, tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations); diff != "" {
			t.Fatalf("unexpected service account annotations (-got +want):\n%s", diff)
		}
		if sa.Name != tsr.Spec.StatefulSet.Pod.ServiceAccount.Name {
			t.Fatalf("unexpected service account name: got %q, want %q", sa.Name, tsr.Spec.StatefulSet.Pod.ServiceAccount.Name)
		}

		expectMissing[corev1.ServiceAccount](t, fc, tsNamespace, tsr.Name)
	})

	t.Run("populate_node_info_in_state_secret_and_see_it_appear_in_status", func(t *testing.T) {

		const key = "profile-abc"
		for replica := range *tsr.Spec.Replicas {
			bytes, err := json.Marshal(map[string]any{
				"Config": map[string]any{
					"NodeID": fmt.Sprintf("node-%d", replica),
					"UserProfile": map[string]any{
						"LoginName": fmt.Sprintf("test-%d.example.ts.net", replica),
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			name := fmt.Sprintf("%s-%d", "test", replica)
			mustUpdate(t, fc, tsNamespace, name, func(s *corev1.Secret) {
				s.Data = map[string][]byte{
					currentProfileKey: []byte(key),
					key:               bytes,
				}
			})
		}

		expectReconciled(t, reconciler, "", tsr.Name)
		tsr.Status.Devices = []tsapi.RecorderTailnetDevice{
			{
				Hostname:   "hostname-node-0",
				TailnetIPs: []string{"1.2.3.4", "::1"},
				URL:        "https://test-0.example.ts.net",
			},
			{
				Hostname:   "hostname-node-1",
				TailnetIPs: []string{"1.2.3.4", "::1"},
				URL:        "https://test-1.example.ts.net",
			},
			{
				Hostname:   "hostname-node-2",
				TailnetIPs: []string{"1.2.3.4", "::1"},
				URL:        "https://test-2.example.ts.net",
			},
		}
		expectEqual(t, fc, tsr)
	})

	t.Run("delete_the_Recorder_and_observe_cleanup", func(t *testing.T) {
		if err := fc.Delete(context.Background(), tsr); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", tsr.Name)

		expectMissing[tsapi.Recorder](t, fc, "", tsr.Name)
		if expected := 0; reconciler.recorders.Len() != expected {
			t.Fatalf("expected %d recorders, got %d", expected, reconciler.recorders.Len())
		}
		if diff := cmp.Diff(tsClient.deleted, []string{"node-0", "node-1", "node-2"}); diff != "" {
			t.Fatalf("unexpected deleted devices (-got +want):\n%s", diff)
		}
		// The fake client does not clean up objects whose owner has been
		// deleted, so we can't test for the owned resources getting deleted.
	})
}

func expectRecorderResources(t *testing.T, fc client.WithWatch, tsr *tsapi.Recorder, shouldExist bool) {
	t.Helper()

	var replicas int32 = 1
	if tsr.Spec.Replicas != nil {
		replicas = *tsr.Spec.Replicas
	}

	role := tsrRole(tsr, tsNamespace)
	roleBinding := tsrRoleBinding(tsr, tsNamespace)
	serviceAccount := tsrServiceAccount(tsr, tsNamespace)
	statefulSet := tsrStatefulSet(tsr, tsNamespace, tsLoginServer)

	if shouldExist {
		expectEqual(t, fc, role)
		expectEqual(t, fc, roleBinding)
		expectEqual(t, fc, serviceAccount)
		expectEqual(t, fc, statefulSet, removeResourceReqs)
	} else {
		expectMissing[rbacv1.Role](t, fc, role.Namespace, role.Name)
		expectMissing[rbacv1.RoleBinding](t, fc, roleBinding.Namespace, roleBinding.Name)
		expectMissing[corev1.ServiceAccount](t, fc, serviceAccount.Namespace, serviceAccount.Name)
		expectMissing[appsv1.StatefulSet](t, fc, statefulSet.Namespace, statefulSet.Name)
	}

	for replica := range replicas {
		auth := tsrAuthSecret(tsr, tsNamespace, "secret-authkey", replica)
		state := tsrStateSecret(tsr, tsNamespace, replica)

		if shouldExist {
			expectEqual(t, fc, auth)
			expectEqual(t, fc, state)
		} else {
			expectMissing[corev1.Secret](t, fc, auth.Namespace, auth.Name)
			expectMissing[corev1.Secret](t, fc, state.Namespace, state.Name)
		}
	}
}
