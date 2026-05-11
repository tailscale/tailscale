// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package recorder

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/client/tailscale/v2"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/tsclient"
	"tailscale.com/tstest"
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

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(tsr).
		WithStatusSubresource(tsr).
		Build()
	tsClient := &fakeTSClient{loginURL: tsLoginServer}
	zl, _ := zap.NewDevelopment()
	fr := record.NewFakeRecorder(2)
	cl := tstest.NewClock(tstest.ClockOpts{})
	reconciler := NewReconciler(ReconcilerOptions{
		Client:             fc,
		Clients:            tsclient.NewProvider(tsClient),
		Recorder:           fr,
		TailscaleNamespace: tsNamespace,
		Logger:             zl.Sugar(),
		Clock:              cl,
	})

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

		tsClient.devices = []tailscale.Device{
			{
				ID:        "node-0",
				Hostname:  "hostname-node-0",
				Addresses: []string{"1.2.3.4", "::1"},
			},
			{
				ID:        "node-1",
				Hostname:  "hostname-node-1",
				Addresses: []string{"1.2.3.4", "::1"},
			},
			{
				ID:        "node-2",
				Hostname:  "hostname-node-2",
				Addresses: []string{"1.2.3.4", "::1"},
			},
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
		auth := tsrAuthSecret(tsr, tsNamespace, "new-authkey", replica)
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

// Test helpers.

func mustCreate(t *testing.T, cl client.Client, obj client.Object) {
	t.Helper()
	if err := cl.Create(context.Background(), obj); err != nil {
		t.Fatalf("creating %q: %v", obj.GetName(), err)
	}
}

func mustUpdate[T any, O ptrObject[T]](t *testing.T, cl client.Client, ns, name string, update func(O)) {
	t.Helper()
	obj := O(new(T))
	if err := cl.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: ns,
	}, obj); err != nil {
		t.Fatalf("getting %q: %v", name, err)
	}
	update(obj)
	if err := cl.Update(context.Background(), obj); err != nil {
		t.Fatalf("updating %q: %v", name, err)
	}
}

func expectEqual[T any, O ptrObject[T]](t *testing.T, cl client.Client, want O, modifiers ...func(O)) {
	t.Helper()
	got := O(new(T))
	if err := cl.Get(context.Background(), types.NamespacedName{
		Name:      want.GetName(),
		Namespace: want.GetNamespace(),
	}, got); err != nil {
		t.Fatalf("getting %q: %v", want.GetName(), err)
	}
	got.SetResourceVersion("")
	want.SetResourceVersion("")
	for _, modifier := range modifiers {
		modifier(want)
		modifier(got)
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected %s (-got +want):\n%s", reflect.TypeOf(want).Elem().Name(), diff)
	}
}

func expectMissing[T any, O ptrObject[T]](t *testing.T, cl client.Client, ns, name string) {
	t.Helper()
	obj := O(new(T))
	err := cl.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: ns,
	}, obj)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("%s %s/%s unexpectedly present, wanted missing", reflect.TypeOf(obj).Elem().Name(), ns, name)
	}
}

func expectReconciled(t *testing.T, r reconcile.Reconciler, ns, name string) {
	t.Helper()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: ns,
			Name:      name,
		},
	}
	res, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if res.Requeue {
		t.Fatalf("unexpected immediate requeue")
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("unexpected timed requeue (%v)", res.RequeueAfter)
	}
}

func expectEvents(t *testing.T, rec *record.FakeRecorder, wantsEvents []string) {
	t.Helper()
	seenEvents := make([]string, 0)
	for range len(wantsEvents) {
		timer := time.NewTimer(time.Second * 5)
		defer timer.Stop()
		select {
		case gotEvent := <-rec.Events:
			if slices.Contains(wantsEvents, gotEvent) {
				seenEvents = append(seenEvents, gotEvent)
			} else {
				t.Errorf("got unexpected event %q, expected events: %+#v", gotEvent, wantsEvents)
			}
		case <-timer.C:
			t.Errorf("timeout waiting for an event, wants events %#+v, got events %+#v", wantsEvents, seenEvents)
		}
	}
}

func removeResourceReqs(sts *appsv1.StatefulSet) {
	if sts != nil {
		sts.Spec.Template.Spec.Resources = nil
	}
}

// fakeTSClient implements tsclient.Client for tests.
type fakeTSClient struct {
	sync.Mutex
	loginURL    string
	keyRequests []tailscale.KeyCapabilities
	deleted     []string
	devices     []tailscale.Device
}

func (c *fakeTSClient) Devices() tsclient.DeviceResource {
	return &fakeDevices{
		deleted: &c.deleted,
		devices: &c.devices,
	}
}

func (c *fakeTSClient) Keys() tsclient.KeyResource {
	return &fakeKeys{keyRequests: &c.keyRequests}
}

func (c *fakeTSClient) VIPServices() tsclient.VIPServiceResource {
	return &fakeVIPServices{}
}

func (c *fakeTSClient) LoginURL() string { return c.loginURL }

type fakeDevices struct {
	deleted *[]string
	devices *[]tailscale.Device
}

func (m *fakeDevices) Delete(_ context.Context, id string) error {
	*m.deleted = append(*m.deleted, id)
	return tailscale.APIError{Status: 404}
}

func (m *fakeDevices) List(_ context.Context, _ ...tailscale.ListDevicesOptions) ([]tailscale.Device, error) {
	return *m.devices, nil
}

func (m *fakeDevices) Get(_ context.Context, id string) (*tailscale.Device, error) {
	if m.devices == nil {
		return nil, tailscale.APIError{Status: 404}
	}
	for _, dev := range *m.devices {
		if dev.ID == id {
			return &dev, nil
		}
	}
	return nil, tailscale.APIError{Status: 404}
}

type fakeKeys struct {
	keyRequests *[]tailscale.KeyCapabilities
}

func (m *fakeKeys) CreateAuthKey(_ context.Context, ckr tailscale.CreateKeyRequest) (*tailscale.Key, error) {
	*m.keyRequests = append(*m.keyRequests, ckr.Capabilities)
	return &tailscale.Key{Key: "new-authkey"}, nil
}

func (m *fakeKeys) List(_ context.Context, _ bool) ([]tailscale.Key, error) { return nil, nil }

type fakeVIPServices struct{}

func (f *fakeVIPServices) List(_ context.Context) ([]tailscale.VIPService, error)          { return nil, nil }
func (f *fakeVIPServices) Delete(_ context.Context, _ string) error                        { return nil }
func (f *fakeVIPServices) Get(_ context.Context, _ string) (*tailscale.VIPService, error)  { return nil, nil }
func (f *fakeVIPServices) CreateOrUpdate(_ context.Context, _ tailscale.VIPService) error { return nil }

// Ensure *Reconciler can be used as a rate.Limiter holder.
var _ = (*rate.Limiter)(nil)
