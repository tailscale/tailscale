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
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/k8s-operator/apis/v1alpha1"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/ptr"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
)

func TestLoadBalancerClass(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger:   zl.Sugar(),
		clock:    clock,
		recorder: record.NewFakeRecorder(100),
	}

	// Create a service that we should manage, but start with a miconfiguration
	// in the annotations.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetFQDN: "invalid.example.com",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
	})

	expectReconciled(t, sr, "default", "test")

	// The expected value of .status.conditions[0].LastTransitionTime until the
	// proxy becomes ready.
	t0 := conditionTime(clock)

	// Should have an error about invalid config.
	want := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetFQDN: "invalid.example.com",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
		Status: corev1.ServiceStatus{
			Conditions: []metav1.Condition{{
				Type:               string(tsapi.ProxyReady),
				Status:             metav1.ConditionFalse,
				LastTransitionTime: t0,
				Reason:             reasonProxyInvalid,
				Message:            `unable to provision proxy resources: invalid Service: invalid value of annotation tailscale.com/tailnet-fqdn: "invalid.example.com" does not appear to be a valid MagicDNS name`,
			}},
		},
	}
	expectEqual(t, fc, want)

	// Delete the misconfiguration so the proxy starts getting created on the
	// next reconcile.
	mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
		s.ObjectMeta.Annotations = nil
	})

	clock.Advance(time.Second)
	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	opts := configOpts{
		replicas:        ptr.To[int32](1),
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		app:             kubetypes.AppIngressProxy,
	}

	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	want.Annotations = nil
	want.ObjectMeta.Finalizers = []string{"tailscale.com/finalizer"}
	want.Status = corev1.ServiceStatus{
		Conditions: []metav1.Condition{{
			Type:               string(tsapi.ProxyReady),
			Status:             metav1.ConditionFalse,
			LastTransitionTime: t0, // Status is still false, no update to transition time
			Reason:             reasonProxyPending,
			Message:            "no Tailscale hostname known yet, waiting for proxy pod to finish auth",
		}},
	}
	expectEqual(t, fc, want)

	// Normally the Tailscale proxy pod would come up here and write its info
	// into the secret. Simulate that, then verify reconcile again and verify
	// that we get to the end.
	mustUpdate(t, fc, "operator-ns", fullName, func(s *corev1.Secret) {
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		s.Data["device_id"] = []byte("ts-id-1234")
		s.Data["device_fqdn"] = []byte("tailscale.device.name.")
		s.Data["device_ips"] = []byte(`["100.99.98.97", "2c0a:8083:94d4:2012:3165:34a5:3616:5fdf"]`)
	})
	clock.Advance(time.Second)
	expectReconciled(t, sr, "default", "test")
	want.Status.Conditions = proxyCreatedCondition(clock)
	want.Status.LoadBalancer = corev1.LoadBalancerStatus{
		Ingress: []corev1.LoadBalancerIngress{
			{
				Hostname: "tailscale.device.name",
			},
			{
				IP: "100.99.98.97",
			},
		},
	}

	// Perform an additional reconciliation loop here to ensure resources don't change through side effects. Mainly
	// to prevent infinite reconciliation
	expectReconciled(t, sr, "default", "test")
	expectEqual(t, fc, want)

	// Turn the service back into a ClusterIP service, which should make the
	// operator clean up.
	mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
		s.Spec.Type = corev1.ServiceTypeClusterIP
		s.Spec.LoadBalancerClass = nil
	})
	mustUpdateStatus(t, fc, "default", "test", func(s *corev1.Service) {
		// Fake client doesn't automatically delete the LoadBalancer status when
		// changing away from the LoadBalancer type, we have to do
		// controller-manager's work by hand.
		s.Status = corev1.ServiceStatus{}
	})
	// synchronous StatefulSet deletion triggers a requeue. But, the StatefulSet
	// didn't create any child resources since this is all faked, so the
	// deletion goes through immediately.
	expectReconciled(t, sr, "default", "test")
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	// The deletion triggers another reconcile, to finish the cleanup.
	expectReconciled(t, sr, "default", "test")
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Service](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)

	// Note that the Tailscale-specific condition status should be gone now.
	want = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
	}
	expectEqual(t, fc, want)
}

func TestTailnetTargetFQDNAnnotation(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tailnetTargetFQDN := "foo.bar.ts.net."
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	// Create a service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetFQDN: tailnetTargetFQDN,
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"foo": "bar",
			},
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	o := configOpts{
		replicas:          ptr.To[int32](1),
		stsName:           shortName,
		secretName:        fullName,
		namespace:         "default",
		parentType:        "svc",
		tailnetTargetFQDN: tailnetTargetFQDN,
		hostname:          "default-test",
		app:               kubetypes.AppEgressProxy,
	}

	expectEqual(t, fc, expectedSecret(t, fc, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)
	want := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{"tailscale.com/finalizer"},
			UID:        types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetFQDN: tailnetTargetFQDN,
			},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: fmt.Sprintf("%s.operator-ns.svc.cluster.local", shortName),
			Type:         corev1.ServiceTypeExternalName,
			Selector:     nil,
		},
		Status: corev1.ServiceStatus{
			Conditions: proxyCreatedCondition(clock),
		},
	}
	expectEqual(t, fc, want)
	expectEqual(t, fc, expectedSecret(t, fc, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)

	// Change the tailscale-target-fqdn annotation which should update the
	// StatefulSet
	tailnetTargetFQDN = "bar.baz.ts.net"
	mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
		s.ObjectMeta.Annotations = map[string]string{
			AnnotationTailnetTargetFQDN: tailnetTargetFQDN,
		}
	})

	// Remove the tailscale-target-fqdn annotation which should make the
	// operator clean up
	mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
		s.ObjectMeta.Annotations = map[string]string{}
	})
	expectReconciled(t, sr, "default", "test")

	// // synchronous StatefulSet deletion triggers a requeue. But, the StatefulSet
	// // didn't create any child resources since this is all faked, so the
	// // deletion goes through immediately.
	expectReconciled(t, sr, "default", "test")
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	// // The deletion triggers another reconcile, to finish the cleanup.
	expectReconciled(t, sr, "default", "test")
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Service](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)
}

func TestTailnetTargetIPAnnotation(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tailnetTargetIP := "100.66.66.66"
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	// Create a service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetIP: tailnetTargetIP,
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"foo": "bar",
			},
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	o := configOpts{
		replicas:        ptr.To[int32](1),
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		tailnetTargetIP: tailnetTargetIP,
		hostname:        "default-test",
		app:             kubetypes.AppEgressProxy,
	}

	expectEqual(t, fc, expectedSecret(t, fc, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)
	want := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{"tailscale.com/finalizer"},
			UID:        types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetIP: tailnetTargetIP,
			},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: fmt.Sprintf("%s.operator-ns.svc.cluster.local", shortName),
			Type:         corev1.ServiceTypeExternalName,
			Selector:     nil,
		},
		Status: corev1.ServiceStatus{
			Conditions: proxyCreatedCondition(clock),
		},
	}
	expectEqual(t, fc, want)
	expectEqual(t, fc, expectedSecret(t, fc, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)

	// Change the tailscale-target-ip annotation which should update the
	// StatefulSet
	tailnetTargetIP = "100.77.77.77"
	mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
		s.ObjectMeta.Annotations = map[string]string{
			AnnotationTailnetTargetIP: tailnetTargetIP,
		}
	})

	// Remove the tailscale-target-ip annotation which should make the
	// operator clean up
	mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
		s.ObjectMeta.Annotations = map[string]string{}
	})
	expectReconciled(t, sr, "default", "test")

	// // synchronous StatefulSet deletion triggers a requeue. But, the StatefulSet
	// // didn't create any child resources since this is all faked, so the
	// // deletion goes through immediately.
	expectReconciled(t, sr, "default", "test")
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	// // The deletion triggers another reconcile, to finish the cleanup.
	expectReconciled(t, sr, "default", "test")
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Service](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)
}

func TestTailnetTargetIPAnnotation_IPCouldNotBeParsed(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger:   zl.Sugar(),
		clock:    clock,
		recorder: record.NewFakeRecorder(100),
	}
	tailnetTargetIP := "invalid-ip"
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",

			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetIP: tailnetTargetIP,
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
	})

	expectReconciled(t, sr, "default", "test")

	t0 := conditionTime(clock)

	want := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetIP: tailnetTargetIP,
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
		Status: corev1.ServiceStatus{
			Conditions: []metav1.Condition{{
				Type:               string(tsapi.ProxyReady),
				Status:             metav1.ConditionFalse,
				LastTransitionTime: t0,
				Reason:             reasonProxyInvalid,
				Message:            `unable to provision proxy resources: invalid Service: invalid value of annotation tailscale.com/tailnet-ip: "invalid-ip" could not be parsed as a valid IP Address, error: ParseAddr("invalid-ip"): unable to parse IP`,
			}},
		},
	}

	expectEqual(t, fc, want)
}

func TestTailnetTargetIPAnnotation_InvalidIP(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger:   zl.Sugar(),
		clock:    clock,
		recorder: record.NewFakeRecorder(100),
	}
	tailnetTargetIP := "999.999.999.999"
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",

			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetIP: tailnetTargetIP,
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
	})

	expectReconciled(t, sr, "default", "test")

	t0 := conditionTime(clock)

	want := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetIP: tailnetTargetIP,
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
		Status: corev1.ServiceStatus{
			Conditions: []metav1.Condition{{
				Type:               string(tsapi.ProxyReady),
				Status:             metav1.ConditionFalse,
				LastTransitionTime: t0,
				Reason:             reasonProxyInvalid,
				Message:            `unable to provision proxy resources: invalid Service: invalid value of annotation tailscale.com/tailnet-ip: "999.999.999.999" could not be parsed as a valid IP Address, error: ParseAddr("999.999.999.999"): IPv4 field has value >255`,
			}},
		},
	}

	expectEqual(t, fc, want)
}

func TestAnnotations(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	// Create a service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/expose": "true",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	o := configOpts{
		replicas:        ptr.To[int32](1),
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		app:             kubetypes.AppIngressProxy,
	}

	expectEqual(t, fc, expectedSecret(t, fc, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)
	want := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{"tailscale.com/finalizer"},
			UID:        types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/expose": "true",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
		Status: corev1.ServiceStatus{
			Conditions: proxyCreatedCondition(clock),
		},
	}
	expectEqual(t, fc, want)

	// Turn the service back into a ClusterIP service, which should make the
	// operator clean up.
	mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
		delete(s.ObjectMeta.Annotations, "tailscale.com/expose")
	})
	// synchronous StatefulSet deletion triggers a requeue. But, the StatefulSet
	// didn't create any child resources since this is all faked, so the
	// deletion goes through immediately.
	expectReconciled(t, sr, "default", "test")
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	// Second time around, the rest of cleanup happens.
	expectReconciled(t, sr, "default", "test")
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Service](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)
	want = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
	}
	expectEqual(t, fc, want)
}

func TestAnnotationIntoLB(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	// Create a service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/expose": "true",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	o := configOpts{
		replicas:        ptr.To[int32](1),
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		app:             kubetypes.AppIngressProxy,
	}

	expectEqual(t, fc, expectedSecret(t, fc, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)

	// Normally the Tailscale proxy pod would come up here and write its info
	// into the secret. Simulate that, since it would have normally happened at
	// this point and the LoadBalancer is going to expect this.
	mustUpdate(t, fc, "operator-ns", fullName, func(s *corev1.Secret) {
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		s.Data["device_id"] = []byte("ts-id-1234")
		s.Data["device_fqdn"] = []byte("tailscale.device.name.")
		s.Data["device_ips"] = []byte(`["100.99.98.97", "2c0a:8083:94d4:2012:3165:34a5:3616:5fdf"]`)
	})
	expectReconciled(t, sr, "default", "test")
	want := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{"tailscale.com/finalizer"},
			UID:        types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/expose": "true",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
		Status: corev1.ServiceStatus{
			Conditions: proxyCreatedCondition(clock),
		},
	}
	expectEqual(t, fc, want)

	// Remove Tailscale's annotation, and at the same time convert the service
	// into a tailscale LoadBalancer.
	mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
		delete(s.ObjectMeta.Annotations, "tailscale.com/expose")
		s.Spec.Type = corev1.ServiceTypeLoadBalancer
		s.Spec.LoadBalancerClass = ptr.To("tailscale")
	})
	expectReconciled(t, sr, "default", "test")
	// None of the proxy machinery should have changed...
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)
	// ... but the service should have a LoadBalancer status.

	want = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{"tailscale.com/finalizer"},
			UID:        types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{
						Hostname: "tailscale.device.name",
					},
					{
						IP: "100.99.98.97",
					},
				},
			},
			Conditions: proxyCreatedCondition(clock),
		},
	}
	expectEqual(t, fc, want)
}

func TestLBIntoAnnotation(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	// Create a service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	o := configOpts{
		replicas:        ptr.To[int32](1),
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		app:             kubetypes.AppIngressProxy,
	}

	expectEqual(t, fc, expectedSecret(t, fc, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)

	// Normally the Tailscale proxy pod would come up here and write its info
	// into the secret. Simulate that, then verify reconcile again and verify
	// that we get to the end.
	mustUpdate(t, fc, "operator-ns", fullName, func(s *corev1.Secret) {
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		s.Data["device_id"] = []byte("ts-id-1234")
		s.Data["device_fqdn"] = []byte("tailscale.device.name.")
		s.Data["device_ips"] = []byte(`["100.99.98.97", "2c0a:8083:94d4:2012:3165:34a5:3616:5fdf"]`)
	})
	expectReconciled(t, sr, "default", "test")
	want := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{"tailscale.com/finalizer"},
			UID:        types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{
						Hostname: "tailscale.device.name",
					},
					{
						IP: "100.99.98.97",
					},
				},
			},
			Conditions: proxyCreatedCondition(clock),
		},
	}
	expectEqual(t, fc, want)

	// Turn the service back into a ClusterIP service, but also add the
	// tailscale annotation.
	mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
		s.ObjectMeta.Annotations = map[string]string{
			"tailscale.com/expose": "true",
		}
		s.Spec.Type = corev1.ServiceTypeClusterIP
		s.Spec.LoadBalancerClass = nil
	})
	mustUpdateStatus(t, fc, "default", "test", func(s *corev1.Service) {
		// Fake client doesn't automatically delete the LoadBalancer status when
		// changing away from the LoadBalancer type, we have to do
		// controller-manager's work by hand.
		s.Status = corev1.ServiceStatus{}
	})
	expectReconciled(t, sr, "default", "test")

	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)

	want = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{"tailscale.com/finalizer"},
			Annotations: map[string]string{
				"tailscale.com/expose": "true",
			},
			UID: types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
		Status: corev1.ServiceStatus{
			Conditions: proxyCreatedCondition(clock),
		},
	}
	expectEqual(t, fc, want)
}

func TestCustomHostname(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	// Create a service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/expose":   "true",
				"tailscale.com/hostname": "reindeer-flotilla",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	o := configOpts{
		replicas:        ptr.To[int32](1),
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "reindeer-flotilla",
		clusterTargetIP: "10.20.30.40",
		app:             kubetypes.AppIngressProxy,
	}

	expectEqual(t, fc, expectedSecret(t, fc, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)
	want := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{"tailscale.com/finalizer"},
			UID:        types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/expose":   "true",
				"tailscale.com/hostname": "reindeer-flotilla",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
		Status: corev1.ServiceStatus{
			Conditions: proxyCreatedCondition(clock),
		},
	}
	expectEqual(t, fc, want)

	// Turn the service back into a ClusterIP service, which should make the
	// operator clean up.
	mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
		delete(s.ObjectMeta.Annotations, "tailscale.com/expose")
	})
	// synchronous StatefulSet deletion triggers a requeue. But, the StatefulSet
	// didn't create any child resources since this is all faked, so the
	// deletion goes through immediately.
	expectReconciled(t, sr, "default", "test")
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	// Second time around, the rest of cleanup happens.
	expectReconciled(t, sr, "default", "test")
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Service](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)
	want = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/hostname": "reindeer-flotilla",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
	}
	expectEqual(t, fc, want)
}

func TestCustomPriorityClassName(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:                 fc,
			tsClient:               ft,
			defaultTags:            []string{"tag:k8s"},
			operatorNamespace:      "operator-ns",
			proxyImage:             "tailscale/tailscale",
			proxyPriorityClassName: "custom-priority-class-name",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	// Create a service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/expose":   "true",
				"tailscale.com/hostname": "tailscale-critical",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	o := configOpts{
		replicas:          ptr.To[int32](1),
		stsName:           shortName,
		secretName:        fullName,
		namespace:         "default",
		parentType:        "svc",
		hostname:          "tailscale-critical",
		priorityClassName: "custom-priority-class-name",
		clusterTargetIP:   "10.20.30.40",
		app:               kubetypes.AppIngressProxy,
	}

	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)
}

func TestServiceProxyClassAnnotation(t *testing.T) {
	cl := tstest.NewClock(tstest.ClockOpts{})
	zl := zap.Must(zap.NewDevelopment())

	pcIfNotPresent := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "if-not-present",
		},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleContainer: &v1alpha1.Container{
						ImagePullPolicy: corev1.PullIfNotPresent,
					},
				},
			},
		},
	}

	pcAlways := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "always",
		},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleContainer: &v1alpha1.Container{
						ImagePullPolicy: corev1.PullAlways,
					},
				},
			},
		},
	}

	builder := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme)
	builder = builder.WithObjects(pcIfNotPresent, pcAlways).
		WithStatusSubresource(pcIfNotPresent, pcAlways)
	fc := builder.Build()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeLoadBalancer,
		},
	}

	mustCreate(t, fc, svc)

	testCases := []struct {
		name                 string
		proxyClassAnnotation string
		proxyClassLabel      string
		proxyClassDefault    string
		expectedProxyClass   string
		expectEvents         []string
	}{
		{
			name:               "via_label",
			proxyClassLabel:    pcIfNotPresent.Name,
			expectedProxyClass: pcIfNotPresent.Name,
		},
		{
			name:                 "via_annotation",
			proxyClassAnnotation: pcIfNotPresent.Name,
			expectedProxyClass:   pcIfNotPresent.Name,
		},
		{
			name:               "via_default",
			proxyClassDefault:  pcIfNotPresent.Name,
			expectedProxyClass: pcIfNotPresent.Name,
		},
		{
			name:                 "via_label_override_annotation",
			proxyClassLabel:      pcIfNotPresent.Name,
			proxyClassAnnotation: pcAlways.Name,
			expectedProxyClass:   pcIfNotPresent.Name,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ft := &fakeTSClient{}

			if tt.proxyClassAnnotation != "" || tt.proxyClassLabel != "" || tt.proxyClassDefault != "" {
				name := tt.proxyClassDefault
				if name == "" {
					name = tt.proxyClassLabel
					if name == "" {
						name = tt.proxyClassAnnotation
					}
				}
				setProxyClassReady(t, fc, cl, name)
			}

			sr := &ServiceReconciler{
				Client: fc,
				ssr: &tailscaleSTSReconciler{
					Client:            fc,
					tsClient:          ft,
					defaultTags:       []string{"tag:k8s"},
					operatorNamespace: "operator-ns",
					proxyImage:        "tailscale/tailscale",
				},
				defaultProxyClass:     tt.proxyClassDefault,
				logger:                zl.Sugar(),
				clock:                 cl,
				isDefaultLoadBalancer: true,
			}

			if tt.proxyClassLabel != "" {
				svc.Labels = map[string]string{
					LabelAnnotationProxyClass: tt.proxyClassLabel,
				}
			}
			if tt.proxyClassAnnotation != "" {
				svc.Annotations = map[string]string{
					LabelAnnotationProxyClass: tt.proxyClassAnnotation,
				}
			}

			mustUpdate(t, fc, svc.Namespace, svc.Name, func(s *corev1.Service) {
				s.Labels = svc.Labels
				s.Annotations = svc.Annotations
			})

			expectReconciled(t, sr, "default", "test")

			list := &corev1.ServiceList{}
			fc.List(context.Background(), list, client.InNamespace("default"))

			for _, i := range list.Items {
				t.Logf("found service %s", i.Name)
			}

			slist := &corev1.SecretList{}
			fc.List(context.Background(), slist, client.InNamespace("operator-ns"))
			for _, i := range slist.Items {
				l, _ := json.Marshal(i.Labels)
				t.Logf("found secret %q with labels %q ", i.Name, string(l))
			}

			_, shortName := findGenName(t, fc, "default", "test", "svc")
			sts := &appsv1.StatefulSet{}
			if err := fc.Get(context.Background(), client.ObjectKey{Namespace: "operator-ns", Name: shortName}, sts); err != nil {
				t.Fatalf("failed to get StatefulSet: %v", err)
			}

			switch tt.expectedProxyClass {
			case pcIfNotPresent.Name:
				for _, cont := range sts.Spec.Template.Spec.Containers {
					if cont.Name == "tailscale" && cont.ImagePullPolicy != corev1.PullIfNotPresent {
						t.Fatalf("ImagePullPolicy %q does not match ProxyClass %q with value %q", cont.ImagePullPolicy, pcIfNotPresent.Name, pcIfNotPresent.Spec.StatefulSet.Pod.TailscaleContainer.ImagePullPolicy)
					}
				}
			case pcAlways.Name:
				for _, cont := range sts.Spec.Template.Spec.Containers {
					if cont.Name == "tailscale" && cont.ImagePullPolicy != corev1.PullAlways {
						t.Fatalf("ImagePullPolicy %q does not match ProxyClass %q with value %q", cont.ImagePullPolicy, pcAlways.Name, pcAlways.Spec.StatefulSet.Pod.TailscaleContainer.ImagePullPolicy)
					}
				}
			default:
				t.Fatalf("unexpected expected ProxyClass %q", tt.expectedProxyClass)
			}
		})
	}
}

func TestProxyClassForService(t *testing.T) {
	// Setup
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-metadata"},
		Spec: tsapi.ProxyClassSpec{
			TailscaleConfig: &tsapi.TailscaleConfig{
				AcceptRoutes: true,
			},
			StatefulSet: &tsapi.StatefulSet{
				Labels:      tsapi.Labels{"foo": "bar"},
				Annotations: map[string]string{"bar.io/foo": "some-val"},
				Pod:         &tsapi.Pod{Annotations: map[string]string{"foo.io/bar": "some-val"}},
			},
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc).
		WithStatusSubresource(pc).
		Build()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	// 1. A new tailscale LoadBalancer Service is created without any
	// ProxyClass. Resources get created for it as usual.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
	})
	expectReconciled(t, sr, "default", "test")
	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	opts := configOpts{
		replicas:        ptr.To[int32](1),
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		app:             kubetypes.AppIngressProxy,
	}
	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// 2. The Service gets updated with tailscale.com/proxy-class label
	// pointing at the 'custom-metadata' ProxyClass. The ProxyClass is not
	// yet ready, so no changes are actually applied to the proxy resources.
	mustUpdate(t, fc, "default", "test", func(svc *corev1.Service) {
		mak.Set(&svc.Labels, LabelAnnotationProxyClass, "custom-metadata")
	})
	expectReconciled(t, sr, "default", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)
	expectEqual(t, fc, expectedSecret(t, fc, opts))

	// 3. ProxyClass is set to Ready, the Service gets reconciled by the
	// services-reconciler and the customization from the ProxyClass is
	// applied to the proxy resources.
	mustUpdateStatus(t, fc, "", "custom-metadata", func(pc *tsapi.ProxyClass) {
		pc.Status = tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassReady),
				ObservedGeneration: pc.Generation,
			}},
		}
	})
	opts.proxyClass = pc.Name
	expectReconciled(t, sr, "default", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)
	expectEqual(t, fc, expectedSecret(t, fc, opts), removeAuthKeyIfExistsModifier(t))

	// 4. tailscale.com/proxy-class label is removed from the Service, the
	// configuration from the ProxyClass is removed from the cluster
	// resources.
	mustUpdate(t, fc, "default", "test", func(svc *corev1.Service) {
		delete(svc.Labels, LabelAnnotationProxyClass)
	})
	opts.proxyClass = ""
	expectReconciled(t, sr, "default", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)
}

func TestDefaultLoadBalancer(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger:                zl.Sugar(),
		clock:                 clock,
		isDefaultLoadBalancer: true,
	}

	// Create a service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeLoadBalancer,
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")

	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	o := configOpts{
		replicas:        ptr.To[int32](1),
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		app:             kubetypes.AppIngressProxy,
	}
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)
}

func TestProxyFirewallMode(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
			tsFirewallMode:    "nftables",
		},
		logger:                zl.Sugar(),
		clock:                 clock,
		isDefaultLoadBalancer: true,
	}

	// Create a service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeLoadBalancer,
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	o := configOpts{
		replicas:        ptr.To[int32](1),
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		firewallMode:    "nftables",
		clusterTargetIP: "10.20.30.40",
		app:             kubetypes.AppIngressProxy,
	}
	expectEqual(t, fc, expectedSTS(t, fc, o), removeResourceReqs)
}

func Test_isMagicDNSName(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{
			in:   "foo.tail4567.ts.net",
			want: true,
		},
		{
			in:   "foo.tail4567.ts.net.",
			want: true,
		},
		{
			in:   "foo.tail4567",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := isMagicDNSName(tt.in); got != tt.want {
				t.Errorf("isMagicDNSName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func Test_serviceHandlerForIngress(t *testing.T) {
	const tailscaleIngressClassName = "tailscale"

	fc := fake.NewFakeClient()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	// 1. An event on a headless Service for a tailscale Ingress results in
	// the Ingress being reconciled.
	mustCreate(t, fc, &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ing-1",
			Namespace: "ns-1",
		},
		Spec: networkingv1.IngressSpec{IngressClassName: ptr.To(tailscaleIngressClassName)},
	})
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "headless-1",
			Namespace: "tailscale",
			Labels: map[string]string{
				kubetypes.LabelManaged: "true",
				LabelParentName:        "ing-1",
				LabelParentNamespace:   "ns-1",
				LabelParentType:        "ingress",
			},
		},
	}
	mustCreate(t, fc, svc1)
	wantReqs := []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: "ns-1", Name: "ing-1"}}}
	gotReqs := serviceHandlerForIngress(fc, zl.Sugar(), tailscaleIngressClassName)(context.Background(), svc1)
	if diff := cmp.Diff(gotReqs, wantReqs); diff != "" {
		t.Fatalf("unexpected reconcile requests (-got +want):\n%s", diff)
	}

	// 2. An event on a Service that is the default backend for a tailscale
	// Ingress results in the Ingress being reconciled.
	mustCreate(t, fc, &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ing-2",
			Namespace: "ns-2",
		},
		Spec: networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{Name: "def-backend"},
			},
			IngressClassName: ptr.To(tailscaleIngressClassName),
		},
	})
	backendSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "def-backend",
			Namespace: "ns-2",
		},
	}
	mustCreate(t, fc, backendSvc)
	wantReqs = []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: "ns-2", Name: "ing-2"}}}
	gotReqs = serviceHandlerForIngress(fc, zl.Sugar(), tailscaleIngressClassName)(context.Background(), backendSvc)
	if diff := cmp.Diff(gotReqs, wantReqs); diff != "" {
		t.Fatalf("unexpected reconcile requests (-got +want):\n%s", diff)
	}

	// 3. An event on a Service that is one of the non-default backends for
	// a tailscale Ingress results in the Ingress being reconciled.
	mustCreate(t, fc, &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ing-3",
			Namespace: "ns-3",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To(tailscaleIngressClassName),
			Rules: []networkingv1.IngressRule{{IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{
					{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "backend"}}},
				},
			}}}},
		},
	})
	backendSvc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "ns-3",
		},
	}
	mustCreate(t, fc, backendSvc2)
	wantReqs = []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: "ns-3", Name: "ing-3"}}}
	gotReqs = serviceHandlerForIngress(fc, zl.Sugar(), tailscaleIngressClassName)(context.Background(), backendSvc2)
	if diff := cmp.Diff(gotReqs, wantReqs); diff != "" {
		t.Fatalf("unexpected reconcile requests (-got +want):\n%s", diff)
	}

	// 4. An event on a Service that is a backend for an Ingress that is not
	// tailscale Ingress does not result in an Ingress reconcile.
	mustCreate(t, fc, &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ing-4",
			Namespace: "ns-4",
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{
					{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "non-ts-backend"}}},
				},
			}}}},
		},
	})
	nonTSBackend := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-ts-backend",
			Namespace: "ns-4",
		},
	}
	mustCreate(t, fc, nonTSBackend)
	gotReqs = serviceHandlerForIngress(fc, zl.Sugar(), tailscaleIngressClassName)(context.Background(), nonTSBackend)
	if len(gotReqs) > 0 {
		t.Errorf("unexpected reconcile request for a Service that does not belong to a Tailscale Ingress: %#+v\n", gotReqs)
	}

	// 5. An event on a Service not related to any Ingress does not result
	// in an Ingress reconcile.
	someSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "some-svc",
			Namespace: "ns-4",
		},
	}
	mustCreate(t, fc, someSvc)
	gotReqs = serviceHandlerForIngress(fc, zl.Sugar(), tailscaleIngressClassName)(context.Background(), someSvc)
	if len(gotReqs) > 0 {
		t.Errorf("unexpected reconcile request for a Service that does not belong to any Ingress: %#+v\n", gotReqs)
	}
}

func Test_clusterDomainFromResolverConf(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		conf      *resolvconffile.Config
		namespace string
		want      string
	}{
		{
			name: "success- custom domain",
			conf: &resolvconffile.Config{
				SearchDomains: []dnsname.FQDN{toFQDN(t, "foo.svc.department.org.io"), toFQDN(t, "svc.department.org.io"), toFQDN(t, "department.org.io")},
			},
			namespace: "foo",
			want:      "department.org.io",
		},
		{
			name: "success- default domain",
			conf: &resolvconffile.Config{
				SearchDomains: []dnsname.FQDN{toFQDN(t, "foo.svc.cluster.local."), toFQDN(t, "svc.cluster.local."), toFQDN(t, "cluster.local.")},
			},
			namespace: "foo",
			want:      "cluster.local",
		},
		{
			name: "only two search domains found",
			conf: &resolvconffile.Config{
				SearchDomains: []dnsname.FQDN{toFQDN(t, "svc.department.org.io"), toFQDN(t, "department.org.io")},
			},
			namespace: "foo",
			want:      "cluster.local",
		},
		{
			name: "first search domain does not match the expected structure",
			conf: &resolvconffile.Config{
				SearchDomains: []dnsname.FQDN{toFQDN(t, "foo.bar.department.org.io"), toFQDN(t, "svc.department.org.io"), toFQDN(t, "some.other.fqdn")},
			},
			namespace: "foo",
			want:      "cluster.local",
		},
		{
			name: "second search domain does not match the expected structure",
			conf: &resolvconffile.Config{
				SearchDomains: []dnsname.FQDN{toFQDN(t, "foo.svc.department.org.io"), toFQDN(t, "foo.department.org.io"), toFQDN(t, "some.other.fqdn")},
			},
			namespace: "foo",
			want:      "cluster.local",
		},
		{
			name: "third search domain does not match the expected structure",
			conf: &resolvconffile.Config{
				SearchDomains: []dnsname.FQDN{toFQDN(t, "foo.svc.department.org.io"), toFQDN(t, "svc.department.org.io"), toFQDN(t, "some.other.fqdn")},
			},
			namespace: "foo",
			want:      "cluster.local",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clusterDomainFromResolverConf(tt.conf, tt.namespace, zl.Sugar()); got != tt.want {
				t.Errorf("clusterDomainFromResolverConf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authKeyRemoval(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	// 1. A new Service that should be exposed via Tailscale gets created, a Secret with a config that contains auth
	// key is generated.
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	opts := configOpts{
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		app:             kubetypes.AppIngressProxy,
		replicas:        ptr.To[int32](1),
	}

	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// 2. Apply update to the Secret that imitates the proxy setting device_id.
	s := expectedSecret(t, fc, opts)
	mustUpdate(t, fc, s.Namespace, s.Name, func(s *corev1.Secret) {
		mak.Set(&s.Data, "device_id", []byte("dkkdi4CNTRL"))
	})

	// 3. Config should no longer contain auth key
	expectReconciled(t, sr, "default", "test")
	opts.shouldRemoveAuthKey = true
	opts.secretExtraData = map[string][]byte{"device_id": []byte("dkkdi4CNTRL")}
	expectEqual(t, fc, expectedSecret(t, fc, opts))
}

func Test_externalNameService(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	// 1. A External name Service that should be exposed via Tailscale gets
	// created.
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	// 1. Create an ExternalName Service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationExpose: "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "foo.com",
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	opts := configOpts{
		replicas:         ptr.To[int32](1),
		stsName:          shortName,
		secretName:       fullName,
		namespace:        "default",
		parentType:       "svc",
		hostname:         "default-test",
		clusterTargetDNS: "foo.com",
		app:              kubetypes.AppIngressProxy,
	}

	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// 2. Change the ExternalName and verify that changes get propagated.
	mustUpdate(t, sr, "default", "test", func(s *corev1.Service) {
		s.Spec.ExternalName = "bar.com"
	})
	expectReconciled(t, sr, "default", "test")
	opts.clusterTargetDNS = "bar.com"
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)
}

func Test_metricsResourceCreation(t *testing.T) {
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "metrics", Generation: 1},
		Spec:       tsapi.ProxyClassSpec{},
		Status: tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassReady),
				ObservedGeneration: 1,
			}},
		},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Labels:    map[string]string{LabelAnnotationProxyClass: "metrics"},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "10.20.30.40",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
	}
	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: serviceMonitorCRD}}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc, svc).
		WithStatusSubresource(pc).
		Build()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			operatorNamespace: "operator-ns",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}
	expectReconciled(t, sr, "default", "test")
	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	opts := configOpts{
		stsName:            shortName,
		secretName:         fullName,
		namespace:          "default",
		parentType:         "svc",
		tailscaleNamespace: "operator-ns",
		hostname:           "default-test",
		namespaced:         true,
		proxyType:          proxyTypeIngressService,
		app:                kubetypes.AppIngressProxy,
		resourceVersion:    "1",
	}

	// 1. Enable metrics- expect metrics Service to be created
	mustUpdate(t, fc, "", "metrics", func(pc *tsapi.ProxyClass) {
		pc.Spec = tsapi.ProxyClassSpec{Metrics: &tsapi.Metrics{Enable: true}}
	})
	expectReconciled(t, sr, "default", "test")
	opts.enableMetrics = true
	expectEqual(t, fc, expectedMetricsService(opts))

	// 2. Enable ServiceMonitor - should not error when there is no ServiceMonitor CRD in cluster
	mustUpdate(t, fc, "", "metrics", func(pc *tsapi.ProxyClass) {
		pc.Spec.Metrics.ServiceMonitor = &tsapi.ServiceMonitor{Enable: true}
	})
	expectReconciled(t, sr, "default", "test")

	// 3. Create ServiceMonitor CRD and reconcile- ServiceMonitor should get created
	mustCreate(t, fc, crd)
	expectReconciled(t, sr, "default", "test")
	expectEqualUnstructured(t, fc, expectedServiceMonitor(t, opts))

	// 4. A change to ServiceMonitor config gets reflected in the ServiceMonitor resource
	mustUpdate(t, fc, "", "metrics", func(pc *tsapi.ProxyClass) {
		pc.Spec.Metrics.ServiceMonitor.Labels = tsapi.Labels{"foo": "bar"}
	})
	expectReconciled(t, sr, "default", "test")
	opts.serviceMonitorLabels = tsapi.Labels{"foo": "bar"}
	opts.resourceVersion = "2"
	expectEqual(t, fc, expectedMetricsService(opts))
	expectEqualUnstructured(t, fc, expectedServiceMonitor(t, opts))

	// 5. Disable metrics- expect metrics Service to be deleted
	mustUpdate(t, fc, "", "metrics", func(pc *tsapi.ProxyClass) {
		pc.Spec.Metrics = nil
	})
	expectReconciled(t, sr, "default", "test")
	expectMissing[corev1.Service](t, fc, "operator-ns", metricsResourceName(opts.stsName))
	// ServiceMonitor gets garbage collected when Service gets deleted (it has OwnerReference of the Service
	// object). We cannot test this using the fake client.
}

func TestIgnorePGService(t *testing.T) {
	// NOTE: creating proxygroup stuff just to be sure that it's all ignored
	_, _, fc, _, _ := setupServiceTest(t)

	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	sr := &ServiceReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
		clock:  clock,
	}

	// Create a service that we should manage, and check that the initial round
	// of objects looks right.
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/proxygroup": "test-pg",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
	})

	expectReconciled(t, sr, "default", "test")

	findNoGenName(t, fc, "default", "test", "svc")
}

func toFQDN(t *testing.T, s string) dnsname.FQDN {
	t.Helper()
	fqdn, err := dnsname.ToFQDN(s)
	if err != nil {
		t.Fatalf("error coverting %q to dnsname.FQDN: %v", s, err)
	}
	return fqdn
}

func proxyCreatedCondition(clock tstime.Clock) []metav1.Condition {
	return []metav1.Condition{{
		Type:               string(tsapi.ProxyReady),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: 0,
		LastTransitionTime: conditionTime(clock),
		Reason:             reasonProxyCreated,
		Message:            reasonProxyCreated,
	}}
}

func conditionTime(clock tstime.Clock) metav1.Time {
	return metav1.NewTime(clock.Now().Truncate(time.Second))
}
