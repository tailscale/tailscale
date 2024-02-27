// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
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
	opts := configOpts{
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		confFileHash:    "6cceb342cd3e1c56cd1bd94c29df63df3653c35fe98a7e7afcdee0dcaa2ad549",
	}

	expectEqual(t, fc, expectedSecret(t, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, opts))

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
	o := configOpts{
		stsName:           shortName,
		secretName:        fullName,
		namespace:         "default",
		parentType:        "svc",
		tailnetTargetFQDN: tailnetTargetFQDN,
		hostname:          "default-test",
		confFileHash:      "6cceb342cd3e1c56cd1bd94c29df63df3653c35fe98a7e7afcdee0dcaa2ad549",
	}

	expectEqual(t, fc, expectedSecret(t, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o))
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
	expectEqual(t, fc, expectedSecret(t, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o))

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
	o := configOpts{
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		tailnetTargetIP: tailnetTargetIP,
		hostname:        "default-test",
		confFileHash:    "6cceb342cd3e1c56cd1bd94c29df63df3653c35fe98a7e7afcdee0dcaa2ad549",
	}

	expectEqual(t, fc, expectedSecret(t, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o))
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
	expectEqual(t, fc, expectedSecret(t, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o))

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
	o := configOpts{
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		confFileHash:    "6cceb342cd3e1c56cd1bd94c29df63df3653c35fe98a7e7afcdee0dcaa2ad549",
	}

	expectEqual(t, fc, expectedSecret(t, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o))
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
	o := configOpts{
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		confFileHash:    "6cceb342cd3e1c56cd1bd94c29df63df3653c35fe98a7e7afcdee0dcaa2ad549",
	}

	expectEqual(t, fc, expectedSecret(t, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o))

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
	// (although configfile hash will change in test env only because we lose auth key due to out test not syncing secret.StringData -> secret.Data)
	o.confFileHash = "fb9006e30ecda75e88c29dcd0ca2dd28a2ae964d001c66e1be3efe159cc3821d"
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o))
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
	o := configOpts{
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		confFileHash:    "6cceb342cd3e1c56cd1bd94c29df63df3653c35fe98a7e7afcdee0dcaa2ad549",
	}

	expectEqual(t, fc, expectedSecret(t, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o))

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

	// configfile hash changes on a re-apply in this case in tests only as
	// we lose the auth key due to the test apply not syncing
	// secret.StringData -> Data.
	o.confFileHash = "fb9006e30ecda75e88c29dcd0ca2dd28a2ae964d001c66e1be3efe159cc3821d"
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o))

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
	o := configOpts{
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "reindeer-flotilla",
		clusterTargetIP: "10.20.30.40",
		confFileHash:    "42376226c7d76ed6d6318315dc6c402f7d993bc0b01a5b0e6c8a833106b7509e",
	}

	expectEqual(t, fc, expectedSecret(t, o))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, o))
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
	o := configOpts{
		stsName:           shortName,
		secretName:        fullName,
		namespace:         "default",
		parentType:        "svc",
		hostname:          "tailscale-critical",
		priorityClassName: "custom-priority-class-name",
		clusterTargetIP:   "10.20.30.40",
		confFileHash:      "13cdef0d5f6f0f2406af028710ea1e0f99f65aba4021e4e70ac75a73cf141fd1",
	}

	expectEqual(t, fc, expectedSTS(t, fc, o))
}

func TestProxyClassForService(t *testing.T) {
	// Setup
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-metadata"},
		Spec: tsapi.ProxyClassSpec{StatefulSet: &tsapi.StatefulSet{
			Labels:      map[string]string{"foo": "bar"},
			Annotations: map[string]string{"bar.io/foo": "some-val"},
			Pod:         &tsapi.Pod{Annotations: map[string]string{"foo.io/bar": "some-val"}}}},
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
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		confFileHash:    "6cceb342cd3e1c56cd1bd94c29df63df3653c35fe98a7e7afcdee0dcaa2ad549",
	}
	expectEqual(t, fc, expectedSecret(t, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, opts))

	// 2. The Service gets updated with tailscale.com/proxy-class label
	// pointing at the 'custom-metadata' ProxyClass. The ProxyClass is not
	// yet ready, so no changes are actually applied to the proxy resources.
	mustUpdate(t, fc, "default", "test", func(svc *corev1.Service) {
		mak.Set(&svc.Labels, LabelProxyClass, "custom-metadata")
	})
	expectReconciled(t, sr, "default", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts))

	// 3. ProxyClass is set to Ready, the Service gets reconciled by the
	// services-reconciler and the customization from the ProxyClass is
	// applied to the proxy resources.
	mustUpdateStatus(t, fc, "", "custom-metadata", func(pc *tsapi.ProxyClass) {
		pc.Status = tsapi.ProxyClassStatus{
			Conditions: []tsapi.ConnectorCondition{{
				Status:             metav1.ConditionTrue,
				Type:               tsapi.ProxyClassready,
				ObservedGeneration: pc.Generation,
			}}}
	})
	opts.proxyClass = pc.Name
	// configfile hash changes on a second apply in test env only because we
	// lose auth key due to out test not syncing secret.StringData ->
	// secret.Data
	opts.confFileHash = "fb9006e30ecda75e88c29dcd0ca2dd28a2ae964d001c66e1be3efe159cc3821d"
	expectReconciled(t, sr, "default", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts))

	// 4. tailscale.com/proxy-class label is removed from the Service, the
	// configuration from the ProxyClass is removed from the cluster
	// resources.
	mustUpdate(t, fc, "default", "test", func(svc *corev1.Service) {
		delete(svc.Labels, LabelProxyClass)
	})
	opts.proxyClass = ""
	expectReconciled(t, sr, "default", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts))
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

	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	o := configOpts{
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		confFileHash:    "6cceb342cd3e1c56cd1bd94c29df63df3653c35fe98a7e7afcdee0dcaa2ad549",
	}
	expectEqual(t, fc, expectedSTS(t, fc, o))
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
	o := configOpts{
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		firewallMode:    "nftables",
		clusterTargetIP: "10.20.30.40",
		confFileHash:    "6cceb342cd3e1c56cd1bd94c29df63df3653c35fe98a7e7afcdee0dcaa2ad549",
	}
	expectEqual(t, fc, expectedSTS(t, fc, o))

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
				LabelManaged:         "true",
				LabelParentName:      "ing-1",
				LabelParentNamespace: "ns-1",
				LabelParentType:      "ingress",
			},
		},
	}
	mustCreate(t, fc, svc1)
	wantReqs := []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: "ns-1", Name: "ing-1"}}}
	gotReqs := serviceHandlerForIngress(fc, zl.Sugar())(context.Background(), svc1)
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
	gotReqs = serviceHandlerForIngress(fc, zl.Sugar())(context.Background(), backendSvc)
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
					{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "backend"}}}},
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
	gotReqs = serviceHandlerForIngress(fc, zl.Sugar())(context.Background(), backendSvc2)
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
					{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "non-ts-backend"}}}},
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
	gotReqs = serviceHandlerForIngress(fc, zl.Sugar())(context.Background(), nonTSBackend)
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
	gotReqs = serviceHandlerForIngress(fc, zl.Sugar())(context.Background(), someSvc)
	if len(gotReqs) > 0 {
		t.Errorf("unexpected reconcile request for a Service that does not belong to any Ingress: %#+v\n", gotReqs)
	}
}
