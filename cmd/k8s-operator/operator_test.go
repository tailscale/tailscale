// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
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
		Client:            fc,
		tsClient:          ft,
		defaultTags:       []string{"tag:k8s"},
		operatorNamespace: "operator-ns",
		proxyImage:        "tailscale/tailscale",
		logger:            zl.Sugar(),
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

	fullName, shortName := findGenName(t, fc, "default", "test")

	expectEqual(t, fc, expectedSecret(fullName))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	expectEqual(t, fc, expectedSTS(shortName, fullName, "default-test", ""))

	// Normally the Tailscale proxy pod would come up here and write its info
	// into the secret. Simulate that, then verify reconcile again and verify
	// that we get to the end.
	mustUpdate(t, fc, "operator-ns", fullName, func(s *corev1.Secret) {
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		s.Data["device_id"] = []byte("ts-id-1234")
		s.Data["device_fqdn"] = []byte("tailscale.device.name.")
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

func TestAnnotations(t *testing.T) {
	fc := fake.NewFakeClient()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	sr := &ServiceReconciler{
		Client:            fc,
		tsClient:          ft,
		defaultTags:       []string{"tag:k8s"},
		operatorNamespace: "operator-ns",
		proxyImage:        "tailscale/tailscale",
		logger:            zl.Sugar(),
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

	fullName, shortName := findGenName(t, fc, "default", "test")

	expectEqual(t, fc, expectedSecret(fullName))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	expectEqual(t, fc, expectedSTS(shortName, fullName, "default-test", ""))
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
		Client:            fc,
		tsClient:          ft,
		defaultTags:       []string{"tag:k8s"},
		operatorNamespace: "operator-ns",
		proxyImage:        "tailscale/tailscale",
		logger:            zl.Sugar(),
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

	fullName, shortName := findGenName(t, fc, "default", "test")

	expectEqual(t, fc, expectedSecret(fullName))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	expectEqual(t, fc, expectedSTS(shortName, fullName, "default-test", ""))

	// Normally the Tailscale proxy pod would come up here and write its info
	// into the secret. Simulate that, since it would have normally happened at
	// this point and the LoadBalancer is going to expect this.
	mustUpdate(t, fc, "operator-ns", fullName, func(s *corev1.Secret) {
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		s.Data["device_id"] = []byte("ts-id-1234")
		s.Data["device_fqdn"] = []byte("tailscale.device.name.")
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
	expectEqual(t, fc, expectedSTS(shortName, fullName, "default-test", ""))
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
		Client:            fc,
		tsClient:          ft,
		defaultTags:       []string{"tag:k8s"},
		operatorNamespace: "operator-ns",
		proxyImage:        "tailscale/tailscale",
		logger:            zl.Sugar(),
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

	fullName, shortName := findGenName(t, fc, "default", "test")

	expectEqual(t, fc, expectedSecret(fullName))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	expectEqual(t, fc, expectedSTS(shortName, fullName, "default-test", ""))

	// Normally the Tailscale proxy pod would come up here and write its info
	// into the secret. Simulate that, then verify reconcile again and verify
	// that we get to the end.
	mustUpdate(t, fc, "operator-ns", fullName, func(s *corev1.Secret) {
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		s.Data["device_id"] = []byte("ts-id-1234")
		s.Data["device_fqdn"] = []byte("tailscale.device.name.")
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
	expectEqual(t, fc, expectedSTS(shortName, fullName, "default-test", ""))

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
		Client:            fc,
		tsClient:          ft,
		defaultTags:       []string{"tag:k8s"},
		operatorNamespace: "operator-ns",
		proxyImage:        "tailscale/tailscale",
		logger:            zl.Sugar(),
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

	fullName, shortName := findGenName(t, fc, "default", "test")

	expectEqual(t, fc, expectedSecret(fullName))
	expectEqual(t, fc, expectedHeadlessService(shortName))
	expectEqual(t, fc, expectedSTS(shortName, fullName, "reindeer-flotilla", ""))
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
		Client:                 fc,
		tsClient:               ft,
		defaultTags:            []string{"tag:k8s"},
		operatorNamespace:      "operator-ns",
		proxyImage:             "tailscale/tailscale",
		proxyPriorityClassName: "tailscale-critical",
		logger:                 zl.Sugar(),
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
				"tailscale.com/hostname": "custom-priority-class-name",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
	})

	expectReconciled(t, sr, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test")

	expectEqual(t, fc, expectedSTS(shortName, fullName, "custom-priority-class-name", "tailscale-critical"))
}

func expectedSecret(name string) *corev1.Secret {
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
				"tailscale.com/parent-resource-ns":   "default",
				"tailscale.com/parent-resource-type": "svc",
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

func expectedSTS(stsName, secretName, hostname, priorityClassName string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "StatefulSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      stsName,
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
			ServiceName: stsName,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					DeletionGracePeriodSeconds: ptr.To[int64](10),
					Labels:                     map[string]string{"app": "1234-UID"},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "proxies",
					PriorityClassName:  priorityClassName,
					InitContainers: []corev1.Container{
						{
							Name:    "sysctler",
							Image:   "busybox",
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
							Env: []corev1.EnvVar{
								{Name: "TS_USERSPACE", Value: "false"},
								{Name: "TS_AUTH_ONCE", Value: "true"},
								{Name: "TS_DEST_IP", Value: "10.20.30.40"},
								{Name: "TS_KUBE_SECRET", Value: secretName},
								{Name: "TS_HOSTNAME", Value: hostname},
							},
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

func findGenName(t *testing.T, client client.Client, ns, name string) (full, noSuffix string) {
	t.Helper()
	labels := map[string]string{
		LabelManaged:         "true",
		LabelParentName:      name,
		LabelParentNamespace: ns,
		LabelParentType:      "svc",
	}
	s, err := getSingleObject[corev1.Secret](context.Background(), client, "operator-ns", labels)
	if err != nil {
		t.Fatalf("finding secret for %q: %v", name, err)
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

func expectReconciled(t *testing.T, sr *ServiceReconciler, ns, name string) {
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
	if res.Requeue {
		t.Fatalf("unexpected immediate requeue")
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("unexpected timed requeue (%v)", res.RequeueAfter)
	}
}

func expectRequeue(t *testing.T, sr *ServiceReconciler, ns, name string) {
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
	if res.Requeue {
		t.Fatalf("unexpected immediate requeue")
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected timed requeue, got success")
	}
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
