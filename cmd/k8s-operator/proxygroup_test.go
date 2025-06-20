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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
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
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeEgress,
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
	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: serviceMonitorCRD}}
	opts := configOpts{
		proxyType:          "proxygroup",
		stsName:            pg.Name,
		parentType:         "proxygroup",
		tailscaleNamespace: "tailscale",
		resourceVersion:    "1",
	}

	t.Run("proxyclass_not_ready", func(t *testing.T) {
		expectReconciled(t, reconciler, "", pg.Name)

		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "the ProxyGroup's ProxyClass default-pc is not yet in a ready state, waiting...", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, false, pc)
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
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, pc)
		if expected := 1; reconciler.egressProxyGroups.Len() != expected {
			t.Fatalf("expected %d egress ProxyGroups, got %d", expected, reconciler.egressProxyGroups.Len())
		}
		expectProxyGroupResources(t, fc, pg, true, pc)
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
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, pc)
	})

	t.Run("scale_up_to_3", func(t *testing.T) {
		pg.Spec.Replicas = ptr.To[int32](3)
		mustUpdate(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
			p.Spec = pg.Spec
		})
		expectReconciled(t, reconciler, "", pg.Name)
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "2/3 ProxyGroup pods running", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, pc)

		addNodeIDToStateSecrets(t, fc, pg)
		expectReconciled(t, reconciler, "", pg.Name)
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionTrue, reasonProxyGroupReady, reasonProxyGroupReady, 0, cl, zl.Sugar())
		pg.Status.Devices = append(pg.Status.Devices, tsapi.TailnetDevice{
			Hostname:   "hostname-nodeid-2",
			TailnetIPs: []string{"1.2.3.4", "::1"},
		})
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, pc)
	})

	t.Run("scale_down_to_1", func(t *testing.T) {
		pg.Spec.Replicas = ptr.To[int32](1)
		mustUpdate(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
			p.Spec = pg.Spec
		})

		expectReconciled(t, reconciler, "", pg.Name)

		pg.Status.Devices = pg.Status.Devices[:1] // truncate to only the first device.
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, pc)
	})

	t.Run("enable_metrics", func(t *testing.T) {
		pc.Spec.Metrics = &tsapi.Metrics{Enable: true}
		mustUpdate(t, fc, "", pc.Name, func(p *tsapi.ProxyClass) {
			p.Spec = pc.Spec
		})
		expectReconciled(t, reconciler, "", pg.Name)
		expectEqual(t, fc, expectedMetricsService(opts))
	})
	t.Run("enable_service_monitor_no_crd", func(t *testing.T) {
		pc.Spec.Metrics.ServiceMonitor = &tsapi.ServiceMonitor{Enable: true}
		mustUpdate(t, fc, "", pc.Name, func(p *tsapi.ProxyClass) {
			p.Spec.Metrics = pc.Spec.Metrics
		})
		expectReconciled(t, reconciler, "", pg.Name)
	})
	t.Run("create_crd_expect_service_monitor", func(t *testing.T) {
		mustCreate(t, fc, crd)
		expectReconciled(t, reconciler, "", pg.Name)
		expectEqualUnstructured(t, fc, expectedServiceMonitor(t, opts))
	})

	t.Run("delete_and_cleanup", func(t *testing.T) {
		if err := fc.Delete(context.Background(), pg); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", pg.Name)

		expectMissing[tsapi.ProxyGroup](t, fc, "", pg.Name)
		if expected := 0; reconciler.egressProxyGroups.Len() != expected {
			t.Fatalf("expected %d ProxyGroups, got %d", expected, reconciler.egressProxyGroups.Len())
		}
		// 2 nodes should get deleted as part of the scale down, and then finally
		// the first node gets deleted with the ProxyGroup cleanup.
		if diff := cmp.Diff(tsClient.deleted, []string{"nodeid-1", "nodeid-2", "nodeid-0"}); diff != "" {
			t.Fatalf("unexpected deleted devices (-got +want):\n%s", diff)
		}
		expectMissing[corev1.Service](t, reconciler, "tailscale", metricsResourceName(pg.Name))
		// The fake client does not clean up objects whose owner has been
		// deleted, so we can't test for the owned resources getting deleted.
	})
}

func TestProxyGroupTypes(t *testing.T) {
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Generation: 1,
		},
		Spec: tsapi.ProxyClassSpec{},
	}
	// Passing ProxyGroup as status subresource is a way to get around fake
	// client's limitations for updating resource statuses.
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc).
		WithStatusSubresource(pc, &tsapi.ProxyGroup{}).
		Build()
	mustUpdateStatus(t, fc, "", pc.Name, func(p *tsapi.ProxyClass) {
		p.Status.Conditions = []metav1.Condition{{
			Type:               string(tsapi.ProxyClassReady),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: 1,
		}}
	})

	zl, _ := zap.NewDevelopment()
	reconciler := &ProxyGroupReconciler{
		tsNamespace: tsNamespace,
		proxyImage:  testProxyImage,
		Client:      fc,
		l:           zl.Sugar(),
		tsClient:    &fakeTSClient{},
		clock:       tstest.NewClock(tstest.ClockOpts{}),
	}

	t.Run("egress_type", func(t *testing.T) {
		pg := &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-egress",
				UID:  "test-egress-uid",
			},
			Spec: tsapi.ProxyGroupSpec{
				Type:     tsapi.ProxyGroupTypeEgress,
				Replicas: ptr.To[int32](0),
			},
		}
		mustCreate(t, fc, pg)

		expectReconciled(t, reconciler, "", pg.Name)
		verifyProxyGroupCounts(t, reconciler, 0, 1)

		sts := &appsv1.StatefulSet{}
		if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
			t.Fatalf("failed to get StatefulSet: %v", err)
		}
		verifyEnvVar(t, sts, "TS_INTERNAL_APP", kubetypes.AppProxyGroupEgress)
		verifyEnvVar(t, sts, "TS_EGRESS_PROXIES_CONFIG_PATH", "/etc/proxies")
		verifyEnvVar(t, sts, "TS_ENABLE_HEALTH_CHECK", "true")

		// Verify that egress configuration has been set up.
		cm := &corev1.ConfigMap{}
		cmName := fmt.Sprintf("%s-egress-config", pg.Name)
		if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: cmName}, cm); err != nil {
			t.Fatalf("failed to get ConfigMap: %v", err)
		}

		expectedVolumes := []corev1.Volume{
			{
				Name: cmName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: cmName,
						},
					},
				},
			},
		}

		expectedVolumeMounts := []corev1.VolumeMount{
			{
				Name:      cmName,
				MountPath: "/etc/proxies",
				ReadOnly:  true,
			},
		}

		if diff := cmp.Diff(expectedVolumes, sts.Spec.Template.Spec.Volumes); diff != "" {
			t.Errorf("unexpected volumes (-want +got):\n%s", diff)
		}

		if diff := cmp.Diff(expectedVolumeMounts, sts.Spec.Template.Spec.Containers[0].VolumeMounts); diff != "" {
			t.Errorf("unexpected volume mounts (-want +got):\n%s", diff)
		}

		expectedLifecycle := corev1.Lifecycle{
			PreStop: &corev1.LifecycleHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: kubetypes.EgessServicesPreshutdownEP,
					Port: intstr.FromInt(defaultLocalAddrPort),
				},
			},
		}
		if diff := cmp.Diff(expectedLifecycle, *sts.Spec.Template.Spec.Containers[0].Lifecycle); diff != "" {
			t.Errorf("unexpected lifecycle (-want +got):\n%s", diff)
		}
		if *sts.Spec.Template.DeletionGracePeriodSeconds != deletionGracePeriodSeconds {
			t.Errorf("unexpected deletion grace period seconds %d, want %d", *sts.Spec.Template.DeletionGracePeriodSeconds, deletionGracePeriodSeconds)
		}
	})
	t.Run("egress_type_no_lifecycle_hook_when_local_addr_port_set", func(t *testing.T) {
		pg := &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-egress-no-lifecycle",
				UID:  "test-egress-no-lifecycle-uid",
			},
			Spec: tsapi.ProxyGroupSpec{
				Type:       tsapi.ProxyGroupTypeEgress,
				Replicas:   ptr.To[int32](0),
				ProxyClass: "test",
			},
		}
		mustCreate(t, fc, pg)
		mustUpdate(t, fc, "", pc.Name, func(p *tsapi.ProxyClass) {
			p.Spec.StatefulSet = &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleContainer: &tsapi.Container{
						Env: []tsapi.Env{{
							Name:  "TS_LOCAL_ADDR_PORT",
							Value: "127.0.0.1:8080",
						}},
					},
				},
			}
		})
		expectReconciled(t, reconciler, "", pg.Name)

		sts := &appsv1.StatefulSet{}
		if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
			t.Fatalf("failed to get StatefulSet: %v", err)
		}

		if sts.Spec.Template.Spec.Containers[0].Lifecycle != nil {
			t.Error("lifecycle hook was set when TS_LOCAL_ADDR_PORT was configured via ProxyClass")
		}
	})

	t.Run("ingress_type", func(t *testing.T) {
		pg := &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ingress",
				UID:  "test-ingress-uid",
			},
			Spec: tsapi.ProxyGroupSpec{
				Type:     tsapi.ProxyGroupTypeIngress,
				Replicas: ptr.To[int32](0),
			},
		}
		if err := fc.Create(context.Background(), pg); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", pg.Name)
		verifyProxyGroupCounts(t, reconciler, 1, 2)

		sts := &appsv1.StatefulSet{}
		if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
			t.Fatalf("failed to get StatefulSet: %v", err)
		}
		verifyEnvVar(t, sts, "TS_INTERNAL_APP", kubetypes.AppProxyGroupIngress)
		verifyEnvVar(t, sts, "TS_SERVE_CONFIG", "/etc/proxies/serve-config.json")
		verifyEnvVar(t, sts, "TS_EXPERIMENTAL_CERT_SHARE", "true")

		// Verify ConfigMap volume mount
		cmName := fmt.Sprintf("%s-ingress-config", pg.Name)
		expectedVolume := corev1.Volume{
			Name: cmName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: cmName,
					},
				},
			},
		}

		expectedVolumeMount := corev1.VolumeMount{
			Name:      cmName,
			MountPath: "/etc/proxies",
			ReadOnly:  true,
		}

		if diff := cmp.Diff([]corev1.Volume{expectedVolume}, sts.Spec.Template.Spec.Volumes); diff != "" {
			t.Errorf("unexpected volumes (-want +got):\n%s", diff)
		}

		if diff := cmp.Diff([]corev1.VolumeMount{expectedVolumeMount}, sts.Spec.Template.Spec.Containers[0].VolumeMounts); diff != "" {
			t.Errorf("unexpected volume mounts (-want +got):\n%s", diff)
		}
	})
}

func TestIngressAdvertiseServicesConfigPreserved(t *testing.T) {
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&tsapi.ProxyGroup{}).
		Build()
	reconciler := &ProxyGroupReconciler{
		tsNamespace: tsNamespace,
		proxyImage:  testProxyImage,
		Client:      fc,
		l:           zap.Must(zap.NewDevelopment()).Sugar(),
		tsClient:    &fakeTSClient{},
		clock:       tstest.NewClock(tstest.ClockOpts{}),
	}

	existingServices := []string{"svc1", "svc2"}
	existingConfigBytes, err := json.Marshal(ipn.ConfigVAlpha{
		AdvertiseServices: existingServices,
		Version:           "should-get-overwritten",
	})
	if err != nil {
		t.Fatal(err)
	}

	const pgName = "test-ingress"
	mustCreate(t, fc, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pgConfigSecretName(pgName, 0),
			Namespace: tsNamespace,
		},
		Data: map[string][]byte{
			tsoperator.TailscaledConfigFileName(106): existingConfigBytes,
		},
	})

	mustCreate(t, fc, &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: pgName,
			UID:  "test-ingress-uid",
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:     tsapi.ProxyGroupTypeIngress,
			Replicas: ptr.To[int32](1),
		},
	})
	expectReconciled(t, reconciler, "", pgName)

	expectedConfigBytes, err := json.Marshal(ipn.ConfigVAlpha{
		// Preserved.
		AdvertiseServices: existingServices,

		// Everything else got updated in the reconcile:
		Version:      "alpha0",
		AcceptDNS:    "false",
		AcceptRoutes: "false",
		Locked:       "false",
		Hostname:     ptr.To(fmt.Sprintf("%s-%d", pgName, 0)),
	})
	if err != nil {
		t.Fatal(err)
	}
	expectEqual(t, fc, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pgConfigSecretName(pgName, 0),
			Namespace:       tsNamespace,
			ResourceVersion: "2",
		},
		Data: map[string][]byte{
			tsoperator.TailscaledConfigFileName(106): expectedConfigBytes,
		},
	})
}

func proxyClassesForLEStagingTest() (*tsapi.ProxyClass, *tsapi.ProxyClass, *tsapi.ProxyClass) {
	pcLEStaging := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "le-staging",
			Generation: 1,
		},
		Spec: tsapi.ProxyClassSpec{
			UseLetsEncryptStagingEnvironment: true,
		},
	}

	pcLEStagingFalse := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "le-staging-false",
			Generation: 1,
		},
		Spec: tsapi.ProxyClassSpec{
			UseLetsEncryptStagingEnvironment: false,
		},
	}

	pcOther := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "other",
			Generation: 1,
		},
		Spec: tsapi.ProxyClassSpec{},
	}

	return pcLEStaging, pcLEStagingFalse, pcOther
}

func setProxyClassReady(t *testing.T, fc client.Client, cl *tstest.Clock, name string) *tsapi.ProxyClass {
	t.Helper()
	pc := &tsapi.ProxyClass{}
	if err := fc.Get(context.Background(), client.ObjectKey{Name: name}, pc); err != nil {
		t.Fatal(err)
	}
	pc.Status = tsapi.ProxyClassStatus{
		Conditions: []metav1.Condition{{
			Type:               string(tsapi.ProxyClassReady),
			Status:             metav1.ConditionTrue,
			Reason:             reasonProxyClassValid,
			Message:            reasonProxyClassValid,
			LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
			ObservedGeneration: pc.Generation,
		}},
	}
	if err := fc.Status().Update(context.Background(), pc); err != nil {
		t.Fatal(err)
	}
	return pc
}

func verifyProxyGroupCounts(t *testing.T, r *ProxyGroupReconciler, wantIngress, wantEgress int) {
	t.Helper()
	if r.ingressProxyGroups.Len() != wantIngress {
		t.Errorf("expected %d ingress proxy groups, got %d", wantIngress, r.ingressProxyGroups.Len())
	}
	if r.egressProxyGroups.Len() != wantEgress {
		t.Errorf("expected %d egress proxy groups, got %d", wantEgress, r.egressProxyGroups.Len())
	}
}

func verifyEnvVar(t *testing.T, sts *appsv1.StatefulSet, name, expectedValue string) {
	t.Helper()
	for _, env := range sts.Spec.Template.Spec.Containers[0].Env {
		if env.Name == name {
			if env.Value != expectedValue {
				t.Errorf("expected %s=%s, got %s", name, expectedValue, env.Value)
			}
			return
		}
	}
	t.Errorf("%s environment variable not found", name)
}

func verifyEnvVarNotPresent(t *testing.T, sts *appsv1.StatefulSet, name string) {
	t.Helper()
	for _, env := range sts.Spec.Template.Spec.Containers[0].Env {
		if env.Name == name {
			t.Errorf("environment variable %s should not be present", name)
			return
		}
	}
}

func expectProxyGroupResources(t *testing.T, fc client.WithWatch, pg *tsapi.ProxyGroup, shouldExist bool, proxyClass *tsapi.ProxyClass) {
	t.Helper()

	role := pgRole(pg, tsNamespace)
	roleBinding := pgRoleBinding(pg, tsNamespace)
	serviceAccount := pgServiceAccount(pg, tsNamespace)
	statefulSet, err := pgStatefulSet(pg, tsNamespace, testProxyImage, "auto", proxyClass)
	if err != nil {
		t.Fatal(err)
	}
	statefulSet.Annotations = defaultProxyClassAnnotations

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

	var expectedSecrets []string
	if shouldExist {
		for i := range pgReplicas(pg) {
			expectedSecrets = append(expectedSecrets,
				fmt.Sprintf("%s-%d", pg.Name, i),
				pgConfigSecretName(pg.Name, i),
			)
		}
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

func TestProxyGroupLetsEncryptStaging(t *testing.T) {
	cl := tstest.NewClock(tstest.ClockOpts{})
	zl := zap.Must(zap.NewDevelopment())

	// Set up test cases- most are shared with non-HA Ingress.
	type proxyGroupLETestCase struct {
		leStagingTestCase
		pgType tsapi.ProxyGroupType
	}
	pcLEStaging, pcLEStagingFalse, pcOther := proxyClassesForLEStagingTest()
	sharedTestCases := testCasesForLEStagingTests()
	var tests []proxyGroupLETestCase
	for _, tt := range sharedTestCases {
		tests = append(tests, proxyGroupLETestCase{
			leStagingTestCase: tt,
			pgType:            tsapi.ProxyGroupTypeIngress,
		})
	}
	tests = append(tests, proxyGroupLETestCase{
		leStagingTestCase: leStagingTestCase{
			name:                  "egress_pg_with_staging_proxyclass",
			proxyClassPerResource: "le-staging",
			useLEStagingEndpoint:  false,
		},
		pgType: tsapi.ProxyGroupTypeEgress,
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme)

			pg := &tsapi.ProxyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: tsapi.ProxyGroupSpec{
					Type:       tt.pgType,
					Replicas:   ptr.To[int32](1),
					ProxyClass: tt.proxyClassPerResource,
				},
			}

			// Pre-populate the fake client with ProxyClasses.
			builder = builder.WithObjects(pcLEStaging, pcLEStagingFalse, pcOther, pg).
				WithStatusSubresource(pcLEStaging, pcLEStagingFalse, pcOther, pg)

			fc := builder.Build()

			// If the test case needs a ProxyClass to exist, ensure it is set to Ready.
			if tt.proxyClassPerResource != "" || tt.defaultProxyClass != "" {
				name := tt.proxyClassPerResource
				if name == "" {
					name = tt.defaultProxyClass
				}
				setProxyClassReady(t, fc, cl, name)
			}

			reconciler := &ProxyGroupReconciler{
				tsNamespace:       tsNamespace,
				proxyImage:        testProxyImage,
				defaultTags:       []string{"tag:test"},
				defaultProxyClass: tt.defaultProxyClass,
				Client:            fc,
				tsClient:          &fakeTSClient{},
				l:                 zl.Sugar(),
				clock:             cl,
			}

			expectReconciled(t, reconciler, "", pg.Name)

			// Verify that the StatefulSet created for ProxyGrup has
			// the expected setting for the staging endpoint.
			sts := &appsv1.StatefulSet{}
			if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
				t.Fatalf("failed to get StatefulSet: %v", err)
			}

			if tt.useLEStagingEndpoint {
				verifyEnvVar(t, sts, "TS_DEBUG_ACME_DIRECTORY_URL", letsEncryptStagingEndpoint)
			} else {
				verifyEnvVarNotPresent(t, sts, "TS_DEBUG_ACME_DIRECTORY_URL")
			}
		})
	}
}

type leStagingTestCase struct {
	name string
	// ProxyClass set on ProxyGroup or Ingress resource.
	proxyClassPerResource string
	// Default ProxyClass.
	defaultProxyClass    string
	useLEStagingEndpoint bool
}

// Shared test cases for LE staging endpoint configuration for ProxyGroup and
// non-HA Ingress.
func testCasesForLEStagingTests() []leStagingTestCase {
	return []leStagingTestCase{
		{
			name:                  "with_staging_proxyclass",
			proxyClassPerResource: "le-staging",
			useLEStagingEndpoint:  true,
		},
		{
			name:                  "with_staging_proxyclass_false",
			proxyClassPerResource: "le-staging-false",
			useLEStagingEndpoint:  false,
		},
		{
			name:                  "with_other_proxyclass",
			proxyClassPerResource: "other",
			useLEStagingEndpoint:  false,
		},
		{
			name:                  "no_proxyclass",
			proxyClassPerResource: "",
			useLEStagingEndpoint:  false,
		},
		{
			name:                  "with_default_staging_proxyclass",
			proxyClassPerResource: "",
			defaultProxyClass:     "le-staging",
			useLEStagingEndpoint:  true,
		},
		{
			name:                  "with_default_other_proxyclass",
			proxyClassPerResource: "",
			defaultProxyClass:     "other",
			useLEStagingEndpoint:  false,
		},
		{
			name:                  "with_default_staging_proxyclass_false",
			proxyClassPerResource: "",
			defaultProxyClass:     "le-staging-false",
			useLEStagingEndpoint:  false,
		},
	}
}
