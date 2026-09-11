// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package recorder_test

import (
	"encoding/json"
	"errors"
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

	tailscaleclient "tailscale.com/client/tailscale/v2"

	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/reconcilertest"
	"tailscale.com/k8s-operator/reconciler/recorder"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/util/clientmetric"
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
			Replicas: new(int32(3)),
		},
	}

	fc := reconcilertest.NewClientBuilder().
		WithObjects(tsr).
		WithStatusSubresource(tsr).
		Build()
	tsClient := reconcilertest.NewFakeClient(reconcilertest.WithLoginURL(tsLoginServer))
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	fr := record.NewFakeRecorder(2)
	r := recorder.NewReconciler(recorder.ReconcilerOptions{
		Client:             fc,
		Recorder:           fr,
		TailscaleNamespace: tsNamespace,
		Clients:            reconcilertest.NewFakeClientProvider(tsClient),
		Logger:             zl.Sugar(),
		Clock:              tstest.NewClock(tstest.ClockOpts{}),
	})

	t.Run("invalid_spec_gives_an_error_condition", func(t *testing.T) {
		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		expectReadyCondition(t, fc, tsr.Name, metav1.ConditionFalse, "RecorderInvalid",
			"Recorder is invalid: must either enable UI or use S3 storage to ensure recordings are accessible")
		expectManagedCount(t, 0)
		expectRecorderResources(t, fc, tsr, false)

		reconcilertest.ExpectEvents(t, fr, []string{"Warning RecorderInvalid Recorder is invalid: must either enable UI or use S3 storage to ensure recordings are accessible"})

		tsr.Spec.EnableUI = true
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations = map[string]string{
			"invalid space characters": "test",
		}
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})
		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		reconcilertest.ExpectEvents(t, fr, []string{"Warning RecorderInvalid Recorder is invalid: must use S3 storage when using multiple replicas to ensure recordings are accessible"})

		tsr.Spec.Storage.S3 = &tsapi.S3{}
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})
		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		// Only check part of this error message, because it's defined in an
		// external package and may change.
		got := &tsapi.Recorder{}
		reconcilertest.MustGet(t, fc, "", tsr.Name, got)
		reconcilertest.ExpectConditionStatus(t, got.Status.Conditions, tsapi.RecorderReady, metav1.ConditionFalse, "RecorderInvalid")
		cond := reconcilertest.Condition(t, got.Status.Conditions, tsapi.RecorderReady)
		for _, msg := range []string{cond.Message, <-fr.Events} {
			if !strings.Contains(msg, `"invalid space characters"`) {
				t.Fatalf("expected invalid annotation key in error message, got %q", msg)
			}
		}
	})

	t.Run("conflicting_service_account_config_marked_as_invalid", func(t *testing.T) {
		reconcilertest.MustCreate(t, fc, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pre-existing-sa",
				Namespace: tsNamespace,
			},
		})

		tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations = nil
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Name = "pre-existing-sa"
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		msg := `Recorder is invalid: custom ServiceAccount name "pre-existing-sa" specified but conflicts with a pre-existing ServiceAccount in the tailscale namespace`
		expectReadyCondition(t, fc, tsr.Name, metav1.ConditionFalse, "RecorderInvalid", msg)
		expectManagedCount(t, 0)

		reconcilertest.ExpectEvents(t, fr, []string{"Warning RecorderInvalid " + msg})
	})

	t.Run("observe_Ready_true_status_condition_for_a_valid_spec", func(t *testing.T) {
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Name = ""
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		// Asserted as a literal rather than via recorder.ReasonRecorderCreated: the reason is part of the CRD's
		// observable status, so a rename should fail here rather than silently follow the constant.
		expectReadyCondition(t, fc, tsr.Name, metav1.ConditionTrue, "RecorderCreated", "RecorderCreated")
		expectManagedCount(t, 1)
		expectRecorderResources(t, fc, tsr, true)

		// Every replica's auth key was minted with the default tag, and its
		// StatefulSet is pointed at the login server of its tailnet.
		if got := len(tsClient.CreateAuthKeyCalls()); got != int(*tsr.Spec.Replicas) {
			t.Fatalf("expected %d auth keys to be created, got %d", *tsr.Spec.Replicas, got)
		}
		for _, req := range tsClient.CreateAuthKeyCalls() {
			if diff := cmp.Diff(req.Capabilities.Devices.Create.Tags, []string{"tag:k8s"}); diff != "" {
				t.Errorf("unexpected auth key tags (-got +want):\n%s", diff)
			}
		}

		ss := &appsv1.StatefulSet{}
		reconcilertest.MustGet(t, fc, tsNamespace, tsr.Name, ss)
		if got := envValue(ss, "TSRECORDER_LOGIN_SERVER"); got != tsLoginServer {
			t.Errorf("unexpected login server env value: got %q, want %q", got, tsLoginServer)
		}
	})

	t.Run("valid_service_account_config", func(t *testing.T) {
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Name = "test-sa"
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations = map[string]string{
			"test": "test",
		}
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		expectManagedCount(t, 1)
		expectRecorderResources(t, fc, tsr, true)

		// Get the service account and check the annotations.
		sa := &corev1.ServiceAccount{}
		reconcilertest.MustGet(t, fc, tsNamespace, "test-sa", sa)
		if diff := cmp.Diff(sa.Annotations, tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations); diff != "" {
			t.Fatalf("unexpected service account annotations (-got +want):\n%s", diff)
		}

		// The ServiceAccount named after the Recorder is no longer referenced,
		// so it should have been cleaned up.
		reconcilertest.ExpectMissing[corev1.ServiceAccount](t, fc, tsNamespace, tsr.Name)
	})

	t.Run("populate_node_info_in_state_secret_and_see_it_appear_in_status", func(t *testing.T) {
		for replica := range *tsr.Spec.Replicas {
			seedStateSecret(t, fc, fmt.Sprintf("test-%d", replica), fmt.Sprintf("node-%d", replica), fmt.Sprintf("test-%d.example.ts.net", replica))
		}

		tsClient.SetDevices(
			tailscaleclient.Device{
				ID:        "node-0",
				Hostname:  "hostname-node-0",
				Addresses: []string{"1.2.3.4", "::1"},
			},
			tailscaleclient.Device{
				ID:        "node-1",
				Hostname:  "hostname-node-1",
				Addresses: []string{"1.2.3.4", "::1"},
			},
			tailscaleclient.Device{
				ID:        "node-2",
				Hostname:  "hostname-node-2",
				Addresses: []string{"1.2.3.4", "::1"},
			},
		)

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		want := []tsapi.RecorderTailnetDevice{
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

		got := &tsapi.Recorder{}
		reconcilertest.MustGet(t, fc, "", tsr.Name, got)
		if diff := cmp.Diff(got.Status.Devices, want); diff != "" {
			t.Fatalf("unexpected devices in status (-got +want):\n%s", diff)
		}
	})

	t.Run("scale_down_deletes_dangling_replica_secrets_and_devices", func(t *testing.T) {
		tsr.Spec.Replicas = new(int32(1))
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		// Replicas 1 and 2 are gone from the cluster and from the tailnet;
		// replica 0 is untouched.
		for _, name := range []string{"test-1", "test-auth-1", "test-2", "test-auth-2"} {
			reconcilertest.ExpectMissing[corev1.Secret](t, fc, tsNamespace, name)
		}
		reconcilertest.MustGet(t, fc, tsNamespace, "test-0", &corev1.Secret{})
		if diff := cmp.Diff(tsClient.DeviceDeletes(), []string{"node-1", "node-2"}); diff != "" {
			t.Fatalf("unexpected deleted devices (-got +want):\n%s", diff)
		}

		// The Role should no longer grant access to the scaled-down replicas'
		// Secrets.
		role := &rbacv1.Role{}
		reconcilertest.MustGet(t, fc, tsNamespace, tsr.Name, role)
		if diff := cmp.Diff(role.Rules[0].ResourceNames, []string{"test-0", "test-auth-0"}); diff != "" {
			t.Fatalf("unexpected Role resource names (-got +want):\n%s", diff)
		}
	})

	t.Run("delete_the_Recorder_and_observe_cleanup", func(t *testing.T) {
		reconcilertest.MustDeleteAll(t, fc, tsr)

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		reconcilertest.ExpectMissing[tsapi.Recorder](t, fc, "", tsr.Name)
		expectManagedCount(t, 0)
		if diff := cmp.Diff(tsClient.DeviceDeletes(), []string{"node-1", "node-2", "node-0"}); diff != "" {
			t.Fatalf("unexpected deleted devices (-got +want):\n%s", diff)
		}
		// The fake client does not clean up objects whose owner has been
		// deleted, so we can't test for the owned resources getting deleted.
	})
}

func TestRecorderTailnetUnavailable(t *testing.T) {
	tsr := &tsapi.Recorder{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       tsapi.RecorderSpec{EnableUI: true, Tailnet: "missing"},
	}

	fc := reconcilertest.NewClientBuilder().
		WithObjects(tsr).
		WithStatusSubresource(tsr).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	r := recorder.NewReconciler(recorder.ReconcilerOptions{
		Client:             fc,
		Recorder:           record.NewFakeRecorder(1),
		TailscaleNamespace: tsNamespace,
		Clients:            reconcilertest.NewFailingClientProvider(errors.New(`tailnet "missing" not found`)),
		Logger:             zl.Sugar(),
		Clock:              tstest.NewClock(tstest.ClockOpts{}),
	})

	reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

	got := &tsapi.Recorder{}
	reconcilertest.MustGet(t, fc, "", tsr.Name, got)
	reconcilertest.ExpectCondition(t, got.Status.Conditions, tsapi.RecorderReady,
		metav1.ConditionFalse, "RecorderTailnetUnavailable", `tailnet "missing" not found`)

	// No resources should have been created for a Recorder we can't mint keys
	// for, and no finalizer should have been added.
	reconcilertest.ExpectMissing[appsv1.StatefulSet](t, fc, tsNamespace, tsr.Name)
	if len(got.Finalizers) > 0 {
		t.Fatalf("expected no finalizers, got %v", got.Finalizers)
	}
}

// expectRecorderResources asserts that the full set of resources for each of tsr's replicas either exists or is
// absent.
func expectRecorderResources(t *testing.T, fc client.Client, tsr *tsapi.Recorder, shouldExist bool) {
	t.Helper()

	var replicas int32 = 1
	if tsr.Spec.Replicas != nil {
		replicas = *tsr.Spec.Replicas
	}

	saName := tsr.Name
	if n := tsr.Spec.StatefulSet.Pod.ServiceAccount.Name; n != "" {
		saName = n
	}

	if !shouldExist {
		reconcilertest.ExpectMissing[rbacv1.Role](t, fc, tsNamespace, tsr.Name)
		reconcilertest.ExpectMissing[rbacv1.RoleBinding](t, fc, tsNamespace, tsr.Name)
		reconcilertest.ExpectMissing[corev1.ServiceAccount](t, fc, tsNamespace, saName)
		reconcilertest.ExpectMissing[appsv1.StatefulSet](t, fc, tsNamespace, tsr.Name)
		for replica := range replicas {
			reconcilertest.ExpectMissing[corev1.Secret](t, fc, tsNamespace, fmt.Sprintf("%s-auth-%d", tsr.Name, replica))
			reconcilertest.ExpectMissing[corev1.Secret](t, fc, tsNamespace, fmt.Sprintf("%s-%d", tsr.Name, replica))
		}
		return
	}

	// Every child carries the ownership labels that let the operator find them again and that scope the
	// StatefulSet's selector, so assert them rather than mere existence.
	wantLabels := map[string]string{
		"app.kubernetes.io/name":       "recorder",
		"app.kubernetes.io/instance":   tsr.Name,
		"app.kubernetes.io/managed-by": "tailscale-operator",
	}

	role := &rbacv1.Role{}
	reconcilertest.MustGet(t, fc, tsNamespace, tsr.Name, role)
	expectLabels(t, "Role", role, wantLabels)

	roleBinding := &rbacv1.RoleBinding{}
	reconcilertest.MustGet(t, fc, tsNamespace, tsr.Name, roleBinding)
	expectLabels(t, "RoleBinding", roleBinding, wantLabels)

	sa := &corev1.ServiceAccount{}
	reconcilertest.MustGet(t, fc, tsNamespace, saName, sa)
	expectLabels(t, "ServiceAccount", sa, wantLabels)

	ss := &appsv1.StatefulSet{}
	reconcilertest.MustGet(t, fc, tsNamespace, tsr.Name, ss)
	expectLabels(t, "StatefulSet", ss, wantLabels)
	if diff := cmp.Diff(ss.Spec.Selector.MatchLabels, wantLabels); diff != "" {
		t.Errorf("unexpected StatefulSet selector (-got +want):\n%s", diff)
	}

	for replica := range replicas {
		auth := &corev1.Secret{}
		reconcilertest.MustGet(t, fc, tsNamespace, fmt.Sprintf("%s-auth-%d", tsr.Name, replica), auth)
		expectLabels(t, "auth Secret", auth, wantLabels)

		state := &corev1.Secret{}
		reconcilertest.MustGet(t, fc, tsNamespace, fmt.Sprintf("%s-%d", tsr.Name, replica), state)
		expectLabels(t, "state Secret", state, wantLabels)
	}
}

// expectLabels asserts that obj carries at least the given labels; callers may set additional ones via the spec.
func expectLabels(t *testing.T, kind string, obj client.Object, want map[string]string) {
	t.Helper()
	got := obj.GetLabels()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s %q label %q = %q, want %q", kind, obj.GetName(), k, got[k], v)
		}
	}
}

// expectReadyCondition asserts the Recorder's RecorderReady condition.
func expectReadyCondition(t *testing.T, fc client.Client, name string, status metav1.ConditionStatus, reason, message string) {
	t.Helper()
	tsr := &tsapi.Recorder{}
	reconcilertest.MustGet(t, fc, "", name, tsr)
	reconcilertest.ExpectCondition(t, tsr.Status.Conditions, tsapi.RecorderReady, status, reason, message)
}

// expectManagedCount asserts the number of Recorders the reconciler reports as managed via its clientmetric gauge.
func expectManagedCount(t *testing.T, want int64) {
	t.Helper()
	for _, m := range clientmetric.Metrics() {
		if m.Name() == kubetypes.MetricRecorderCount {
			if got := m.Value(); got != want {
				t.Fatalf("expected %d recorders, got %d", want, got)
			}
			return
		}
	}
	t.Fatalf("metric %q not found", kubetypes.MetricRecorderCount)
}

// seedStateSecret writes the profile data that tailscaled would have written to a replica's state Secret once it has
// authenticated.
func seedStateSecret(t *testing.T, fc client.Client, name, nodeID, loginName string) {
	t.Helper()
	const key = "profile-abc"

	body, err := json.Marshal(map[string]any{
		"Config": map[string]any{
			"NodeID": nodeID,
			"UserProfile": map[string]any{
				"LoginName": loginName,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	reconcilertest.MustUpdate(t, fc, tsNamespace, name, func(s *corev1.Secret) {
		s.Data = map[string][]byte{
			string(ipn.CurrentProfileStateKey): []byte(key),
			key:                                body,
		}
	})
}

func envValue(ss *appsv1.StatefulSet, name string) string {
	for _, env := range ss.Spec.Template.Spec.Containers[0].Env {
		if env.Name == name {
			return env.Value
		}
	}
	return ""
}
