// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/client/tailscale"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
)

const testProxyImage = "tailscale/tailscale:test"

var defaultProxyClassAnnotations = map[string]string{
	"some-annotation": "from-the-proxy-class",
}

func TestProxyGroup(t *testing.T) {
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-pc",
		},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Annotations: defaultProxyClassAnnotations,
			},
		},
	}
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Finalizers: []string{"tailscale.com/finalizer"},
		},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pg, pc).
		WithStatusSubresource(pg, pc).
		Build()
	tsClient := &fakeTSClient{}
	zl, _ := zap.NewDevelopment()
	fr := record.NewFakeRecorder(1)
	cl := tstest.NewClock(tstest.ClockOpts{})
	reconciler := &ProxyGroupReconciler{
		tsNamespace:       tsNamespace,
		proxyImage:        testProxyImage,
		defaultTags:       []string{"tag:test-tag"},
		tsFirewallMode:    "auto",
		defaultProxyClass: "default-pc",

		Client:   fc,
		tsClient: tsClient,
		recorder: fr,
		l:        zl.Sugar(),
		clock:    cl,
	}

	t.Run("proxyclass_not_ready", func(t *testing.T) {
		expectReconciled(t, reconciler, "", pg.Name)

		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "the ProxyGroup's ProxyClass default-pc is not yet in a ready state, waiting...", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg, nil)
	})

	t.Run("observe_ProxyGroupCreating_status_reason", func(t *testing.T) {
		pc.Status = tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Type:               string(tsapi.ProxyClassReady),
				Status:             metav1.ConditionTrue,
				Reason:             reasonProxyClassValid,
				Message:            reasonProxyClassValid,
				LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
			}},
		}
		if err := fc.Status().Update(context.Background(), pc); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", pg.Name)

		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "0/2 ProxyGroup pods running", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg, nil)
		if expected := 1; reconciler.proxyGroups.Len() != expected {
			t.Fatalf("expected %d recorders, got %d", expected, reconciler.proxyGroups.Len())
		}
		expectProxyGroupResources(t, fc, pg, true)
		keyReq := tailscale.KeyCapabilities{
			Devices: tailscale.KeyDeviceCapabilities{
				Create: tailscale.KeyDeviceCreateCapabilities{
					Reusable:      false,
					Ephemeral:     false,
					Preauthorized: true,
					Tags:          []string{"tag:test-tag"},
				},
			},
		}
		if diff := cmp.Diff(tsClient.KeyRequests(), []tailscale.KeyCapabilities{keyReq, keyReq}); diff != "" {
			t.Fatalf("unexpected secrets (-got +want):\n%s", diff)
		}
	})

	t.Run("simulate_successful_device_auth", func(t *testing.T) {
		addNodeIDToStateSecrets(t, fc, pg)
		expectReconciled(t, reconciler, "", pg.Name)

		pg.Status.Devices = []tsapi.TailnetDevice{
			{
				Hostname:   "hostname-nodeid-0",
				TailnetIPs: []string{"1.2.3.4", "::1"},
			},
			{
				Hostname:   "hostname-nodeid-1",
				TailnetIPs: []string{"1.2.3.4", "::1"},
			},
		}
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionTrue, reasonProxyGroupReady, reasonProxyGroupReady, 0, cl, zl.Sugar())
		expectEqual(t, fc, pg, nil)
		expectProxyGroupResources(t, fc, pg, true)
	})

	t.Run("scale_up_to_3", func(t *testing.T) {
		pg.Spec.Replicas = ptr.To[int32](3)
		mustUpdate(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
			p.Spec = pg.Spec
		})
		expectReconciled(t, reconciler, "", pg.Name)
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "2/3 ProxyGroup pods running", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg, nil)

		addNodeIDToStateSecrets(t, fc, pg)
		expectReconciled(t, reconciler, "", pg.Name)
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionTrue, reasonProxyGroupReady, reasonProxyGroupReady, 0, cl, zl.Sugar())
		pg.Status.Devices = append(pg.Status.Devices, tsapi.TailnetDevice{
			Hostname:   "hostname-nodeid-2",
			TailnetIPs: []string{"1.2.3.4", "::1"},
		})
		expectEqual(t, fc, pg, nil)
		expectProxyGroupResources(t, fc, pg, true)
	})

	t.Run("scale_down_to_1", func(t *testing.T) {
		pg.Spec.Replicas = ptr.To[int32](1)
		mustUpdate(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
			p.Spec = pg.Spec
		})
		expectReconciled(t, reconciler, "", pg.Name)
		pg.Status.Devices = pg.Status.Devices[:1] // truncate to only the first device.
		expectEqual(t, fc, pg, nil)

		expectProxyGroupResources(t, fc, pg, true)
	})

	t.Run("delete_and_cleanup", func(t *testing.T) {
		if err := fc.Delete(context.Background(), pg); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", pg.Name)

		expectMissing[tsapi.Recorder](t, fc, "", pg.Name)
		if expected := 0; reconciler.proxyGroups.Len() != expected {
			t.Fatalf("expected %d ProxyGroups, got %d", expected, reconciler.proxyGroups.Len())
		}
		// 2 nodes should get deleted as part of the scale down, and then finally
		// the first node gets deleted with the ProxyGroup cleanup.
		if diff := cmp.Diff(tsClient.deleted, []string{"nodeid-1", "nodeid-2", "nodeid-0"}); diff != "" {
			t.Fatalf("unexpected deleted devices (-got +want):\n%s", diff)
		}
		// The fake client does not clean up objects whose owner has been
		// deleted, so we can't test for the owned resources getting deleted.
	})
}

func expectProxyGroupResources(t *testing.T, fc client.WithWatch, pg *tsapi.ProxyGroup, shouldExist bool) {
	t.Helper()

	role := pgRole(pg, tsNamespace)
	roleBinding := pgRoleBinding(pg, tsNamespace)
	serviceAccount := pgServiceAccount(pg, tsNamespace)
	statefulSet, err := pgStatefulSet(pg, tsNamespace, testProxyImage, "auto", "")
	if err != nil {
		t.Fatal(err)
	}
	statefulSet.Annotations = defaultProxyClassAnnotations

	if shouldExist {
		expectEqual(t, fc, role, nil)
		expectEqual(t, fc, roleBinding, nil)
		expectEqual(t, fc, serviceAccount, nil)
		expectEqual(t, fc, statefulSet, func(ss *appsv1.StatefulSet) {
			ss.Spec.Template.Annotations[podAnnotationLastSetConfigFileHash] = ""
		})
	} else {
		expectMissing[rbacv1.Role](t, fc, role.Namespace, role.Name)
		expectMissing[rbacv1.RoleBinding](t, fc, roleBinding.Namespace, roleBinding.Name)
		expectMissing[corev1.ServiceAccount](t, fc, serviceAccount.Namespace, serviceAccount.Name)
		expectMissing[appsv1.StatefulSet](t, fc, statefulSet.Namespace, statefulSet.Name)
	}

	var expectedSecrets []string
	for i := range pgReplicas(pg) {
		expectedSecrets = append(expectedSecrets,
			fmt.Sprintf("%s-%d", pg.Name, i),
			fmt.Sprintf("%s-%d-config", pg.Name, i),
		)
	}
	expectSecrets(t, fc, expectedSecrets)
}

func expectSecrets(t *testing.T, fc client.WithWatch, expected []string) {
	t.Helper()

	secrets := &corev1.SecretList{}
	if err := fc.List(context.Background(), secrets); err != nil {
		t.Fatal(err)
	}

	var actual []string
	for _, secret := range secrets.Items {
		actual = append(actual, secret.Name)
	}

	if diff := cmp.Diff(actual, expected); diff != "" {
		t.Fatalf("unexpected secrets (-got +want):\n%s", diff)
	}
}

func addNodeIDToStateSecrets(t *testing.T, fc client.WithWatch, pg *tsapi.ProxyGroup) {
	const key = "profile-abc"
	for i := range pgReplicas(pg) {
		bytes, err := json.Marshal(map[string]any{
			"Config": map[string]any{
				"NodeID": fmt.Sprintf("nodeid-%d", i),
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		mustUpdate(t, fc, tsNamespace, fmt.Sprintf("test-%d", i), func(s *corev1.Secret) {
			s.Data = map[string][]byte{
				currentProfileKey: []byte(key),
				key:               bytes,
			}
		})
	}
}
