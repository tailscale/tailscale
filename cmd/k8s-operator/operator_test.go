// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/client/tailscale"
	"tailscale.com/types/ptr"
)

func TestLoadBalancerClass(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
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
		logger: zl.Sugar(),
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

	expectEqual(t, fc, expectedSecret(fullName, "default", "svc"))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o := stsOpts{
		name:       shortName,
		secretName: fullName,
		hostname:   "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))

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
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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
		},
	}
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
	want = &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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

	expectEqual(t, fc, expectedSecret(fullName, "default", "svc"))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o := stsOpts{
		name:              shortName,
		secretName:        fullName,
		tailnetTargetFQDN: tailnetTargetFQDN,
		hostname:          "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))
	want := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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
	}
	expectEqual(t, fc, want)
	expectEqual(t, fc, expectedSecret(fullName, "default", "svc"))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o = stsOpts{
		name:              shortName,
		secretName:        fullName,
		tailnetTargetFQDN: tailnetTargetFQDN,
		hostname:          "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))

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

	expectEqual(t, fc, expectedSecret(fullName, "default", "svc"))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o := stsOpts{
		name:            shortName,
		secretName:      fullName,
		tailnetTargetIP: tailnetTargetIP,
		hostname:        "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))
	want := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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
	}
	expectEqual(t, fc, want)
	expectEqual(t, fc, expectedSecret(fullName, "default", "svc"))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o = stsOpts{
		name:            shortName,
		secretName:      fullName,
		tailnetTargetIP: tailnetTargetIP,
		hostname:        "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))

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

func TestAnnotations(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
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
		logger: zl.Sugar(),
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

	expectEqual(t, fc, expectedSecret(fullName, "default", "svc"))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o := stsOpts{
		name:       shortName,
		secretName: fullName,
		hostname:   "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))
	want := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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

	expectEqual(t, fc, expectedSecret(fullName, "default", "svc"))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o := stsOpts{
		name:       shortName,
		secretName: fullName,
		hostname:   "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))

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
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o = stsOpts{
		name:       shortName,
		secretName: fullName,
		hostname:   "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))
	// ... but the service should have a LoadBalancer status.

	want = &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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

	expectEqual(t, fc, expectedSecret(fullName, "default", "svc"))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o := stsOpts{
		name:       shortName,
		secretName: fullName,
		hostname:   "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))

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
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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

	expectEqual(t, fc, expectedHeadlessService(shortName))
	o = stsOpts{
		name:       shortName,
		secretName: fullName,
		hostname:   "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))

	want = &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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

	expectEqual(t, fc, expectedSecret(fullName, "default", "svc"))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o := stsOpts{
		name:       shortName,
		secretName: fullName,
		hostname:   "reindeer-flotilla",
	}
	expectEqual(t, fc, expectedSTS(o))
	want := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
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
	o := stsOpts{
		name:              shortName,
		secretName:        fullName,
		hostname:          "tailscale-critical",
		priorityClassName: "custom-priority-class-name",
	}

	expectEqual(t, fc, expectedSTS(o))
}

func TestDefaultLoadBalancer(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
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
		logger:                zl.Sugar(),
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

	// expectEqual(t, fc, expectedSecret(fullName, "default", "svc"))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	o := stsOpts{
		name:       shortName,
		secretName: fullName,
		hostname:   "default-test",
	}
	expectEqual(t, fc, expectedSTS(o))
}

func TestProxyFirewallMode(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
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
	o := stsOpts{
		name:         shortName,
		secretName:   fullName,
		hostname:     "default-test",
		firewallMode: "nftables",
	}
	expectEqual(t, fc, expectedSTS(o))

}

func expectedSecret(name, parentNamespace, typ string) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "operator-ns",
			Labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource":      "test",
				"tailscale.com/parent-resource-ns":   parentNamespace,
				"tailscale.com/parent-resource-type": typ,
			},
		},
		StringData: map[string]string{
			"authkey": "secret-authkey",
		},
	}
}

func expectedHeadlessService(name string) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:         name,
			GenerateName: "ts-test-",
			Namespace:    "operator-ns",
			Labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource":      "test",
				"tailscale.com/parent-resource-ns":   "default",
				"tailscale.com/parent-resource-type": "svc",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "1234-UID",
			},
			ClusterIP: "None",
		},
	}
}

func expectedSTS(opts stsOpts) *appsv1.StatefulSet {
	containerEnv := []corev1.EnvVar{
		{Name: "TS_USERSPACE", Value: "false"},
		{Name: "TS_AUTH_ONCE", Value: "true"},
		{Name: "TS_KUBE_SECRET", Value: opts.secretName},
		{Name: "TS_HOSTNAME", Value: opts.hostname},
	}
	annots := map[string]string{
		"tailscale.com/operator-last-set-hostname": opts.hostname,
	}
	if opts.tailnetTargetIP != "" {
		annots["tailscale.com/operator-last-set-ts-tailnet-target-ip"] = opts.tailnetTargetIP
		containerEnv = append(containerEnv, corev1.EnvVar{
			Name:  "TS_TAILNET_TARGET_IP",
			Value: opts.tailnetTargetIP,
		})
	} else if opts.tailnetTargetFQDN != "" {
		annots["tailscale.com/operator-last-set-ts-tailnet-target-fqdn"] = opts.tailnetTargetFQDN
		containerEnv = append(containerEnv, corev1.EnvVar{
			Name:  "TS_TAILNET_TARGET_FQDN",
			Value: opts.tailnetTargetFQDN,
		})

	} else {
		containerEnv = append(containerEnv, corev1.EnvVar{
			Name:  "TS_DEST_IP",
			Value: "10.20.30.40",
		})

		annots["tailscale.com/operator-last-set-cluster-ip"] = "10.20.30.40"

	}
	if opts.firewallMode != "" {
		containerEnv = append(containerEnv, corev1.EnvVar{
			Name:  "TS_DEBUG_FIREWALL_MODE",
			Value: opts.firewallMode,
		})
	}
	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "StatefulSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.name,
			Namespace: "operator-ns",
			Labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource":      "test",
				"tailscale.com/parent-resource-ns":   "default",
				"tailscale.com/parent-resource-type": "svc",
			},
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "1234-UID"},
			},
			ServiceName: opts.name,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations:                annots,
					DeletionGracePeriodSeconds: ptr.To[int64](10),
					Labels:                     map[string]string{"app": "1234-UID"},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "proxies",
					PriorityClassName:  opts.priorityClassName,
					InitContainers: []corev1.Container{
						{
							Name:    "sysctler",
							Image:   "tailscale/tailscale",
							Command: []string{"/bin/sh"},
							Args:    []string{"-c", "sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1"},
							SecurityContext: &corev1.SecurityContext{
								Privileged: ptr.To(true),
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "tailscale",
							Image: "tailscale/tailscale",
							Env:   containerEnv,
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN"},
								},
							},
							ImagePullPolicy: "Always",
						},
					},
				},
			},
		},
	}
}

func findGenName(t *testing.T, client client.Client, ns, name, typ string) (full, noSuffix string) {
	t.Helper()
	labels := map[string]string{
		LabelManaged:         "true",
		LabelParentName:      name,
		LabelParentNamespace: ns,
		LabelParentType:      typ,
	}
	s, err := getSingleObject[corev1.Secret](context.Background(), client, "operator-ns", labels)
	if err != nil {
		t.Fatalf("finding secret for %q: %v", name, err)
	}
	if s == nil {
		t.Fatalf("no secret found for %q %s %+#v", name, ns, labels)
	}
	return s.GetName(), strings.TrimSuffix(s.GetName(), "-0")
}

func mustCreate(t *testing.T, client client.Client, obj client.Object) {
	t.Helper()
	if err := client.Create(context.Background(), obj); err != nil {
		t.Fatalf("creating %q: %v", obj.GetName(), err)
	}
}

func mustUpdate[T any, O ptrObject[T]](t *testing.T, client client.Client, ns, name string, update func(O)) {
	t.Helper()
	obj := O(new(T))
	if err := client.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: ns,
	}, obj); err != nil {
		t.Fatalf("getting %q: %v", name, err)
	}
	update(obj)
	if err := client.Update(context.Background(), obj); err != nil {
		t.Fatalf("updating %q: %v", name, err)
	}
}

func mustUpdateStatus[T any, O ptrObject[T]](t *testing.T, client client.Client, ns, name string, update func(O)) {
	t.Helper()
	obj := O(new(T))
	if err := client.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: ns,
	}, obj); err != nil {
		t.Fatalf("getting %q: %v", name, err)
	}
	update(obj)
	if err := client.Status().Update(context.Background(), obj); err != nil {
		t.Fatalf("updating %q: %v", name, err)
	}
}

func expectEqual[T any, O ptrObject[T]](t *testing.T, client client.Client, want O) {
	t.Helper()
	got := O(new(T))
	if err := client.Get(context.Background(), types.NamespacedName{
		Name:      want.GetName(),
		Namespace: want.GetNamespace(),
	}, got); err != nil {
		t.Fatalf("getting %q: %v", want.GetName(), err)
	}
	// The resource version changes eagerly whenever the operator does even a
	// no-op update. Asserting a specific value leads to overly brittle tests,
	// so just remove it from both got and want.
	got.SetResourceVersion("")
	want.SetResourceVersion("")
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected object (-got +want):\n%s", diff)
	}
}

func expectMissing[T any, O ptrObject[T]](t *testing.T, client client.Client, ns, name string) {
	t.Helper()
	obj := O(new(T))
	if err := client.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: ns,
	}, obj); !apierrors.IsNotFound(err) {
		t.Fatalf("object %s/%s unexpectedly present, wanted missing", ns, name)
	}
}

func expectReconciled(t *testing.T, sr reconcile.Reconciler, ns, name string) {
	t.Helper()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: ns,
			Name:      name,
		},
	}
	res, err := sr.Reconcile(context.Background(), req)
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

func expectRequeue(t *testing.T, sr reconcile.Reconciler, ns, name string) {
	t.Helper()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: ns,
		},
	}
	res, err := sr.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected timed requeue, got success")
	}
}

type stsOpts struct {
	name              string
	secretName        string
	hostname          string
	priorityClassName string
	firewallMode      string
	tailnetTargetIP   string
	tailnetTargetFQDN string
}

type fakeTSClient struct {
	sync.Mutex
	keyRequests []tailscale.KeyCapabilities
	deleted     []string
}

func (c *fakeTSClient) CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error) {
	c.Lock()
	defer c.Unlock()
	c.keyRequests = append(c.keyRequests, caps)
	k := &tailscale.Key{
		ID:           "key",
		Created:      time.Now(),
		Capabilities: caps,
	}
	return "secret-authkey", k, nil
}

func (c *fakeTSClient) DeleteDevice(ctx context.Context, deviceID string) error {
	c.Lock()
	defer c.Unlock()
	c.deleted = append(c.deleted, deviceID)
	return nil
}

func (c *fakeTSClient) KeyRequests() []tailscale.KeyCapabilities {
	c.Lock()
	defer c.Unlock()
	return c.keyRequests
}

func (c *fakeTSClient) Deleted() []string {
	c.Lock()
	defer c.Unlock()
	return c.deleted
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
