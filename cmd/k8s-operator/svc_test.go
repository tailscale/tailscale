// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"slices"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
)

func TestService_DefaultProxyClassInitiallyNotReady(t *testing.T) {
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
	zl := zap.Must(zap.NewDevelopment())
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
		defaultProxyClass: "custom-metadata",
		logger:            zl.Sugar(),
		clock:             clock,
	}

	// 1. A new tailscale LoadBalancer Service is created but the default
	// ProxyClass is not ready yet.
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
			LoadBalancerClass: new("tailscale"),
		},
	})
	expectReconciled(t, sr, "default", "test")
	labels := map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentName:        "test",
		LabelParentNamespace:   "operator-ns",
		LabelParentType:        "svc",
	}
	s, err := getSingleObject[corev1.Secret](context.Background(), fc, "operator-ns", labels)
	if err != nil {
		t.Fatalf("finding Secret for %q: %v", "test", err)
	}
	if s != nil {
		t.Fatalf("expected no Secret to be created when default ProxyClass is not ready, but found one: %v", s)
	}

	// 2. ProxyClass is set to Ready, the Service can become ready now.
	mustUpdateStatus(t, fc, "", "custom-metadata", func(pc *tsapi.ProxyClass) {
		pc.Status = tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassReady),
				ObservedGeneration: pc.Generation,
			}},
		}
	})
	expectReconciled(t, sr, "default", "test")
	fullName, shortName := findGenName(t, fc, "default", "test", "svc")
	opts := configOpts{
		replicas:        new(int32(1)),
		stsName:         shortName,
		secretName:      fullName,
		namespace:       "default",
		parentType:      "svc",
		hostname:        "default-test",
		clusterTargetIP: "10.20.30.40",
		app:             kubetypes.AppIngressProxy,
		proxyClass:      pc.Name,
	}
	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "svc"))
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)
}

func TestProxyClassHandlerForSvc(t *testing.T) {
	svc := func(name string, annotations, labels map[string]string) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   "default",
				Annotations: annotations,
				Labels:      labels,
			},
			Spec: corev1.ServiceSpec{
				ClusterIP: "1.2.3.4",
			},
		}
	}
	lbSvc := func(name string, annotations map[string]string, class *string) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   "foo",
				Annotations: annotations,
			},
			Spec: corev1.ServiceSpec{
				Type:              corev1.ServiceTypeLoadBalancer,
				LoadBalancerClass: class,
				ClusterIP:         "1.2.3.4",
			},
		}
	}

	const (
		defaultPCName      = "default-proxyclass"
		otherPCName        = "other-proxyclass"
		unreferencedPCName = "unreferenced-proxyclass"
	)
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithIndex(&corev1.Service{}, indexServiceProxyClass, indexProxyClass).
		WithIndex(&corev1.Service{}, indexServiceExposed, indexExposed).
		WithIndex(&corev1.Service{}, indexServiceType, indexType).
		WithObjects(
			svc("not-exposed", nil, nil),
			svc("exposed-default", map[string]string{AnnotationExpose: "true"}, nil),
			svc("exposed-other", map[string]string{AnnotationExpose: "true", LabelAnnotationProxyClass: otherPCName}, nil),
			svc("annotated", map[string]string{LabelAnnotationProxyClass: defaultPCName}, nil),
			svc("labelled", nil, map[string]string{LabelAnnotationProxyClass: defaultPCName}),
			lbSvc("lb-svc", nil, new("tailscale")),
			lbSvc("lb-svc-no-class", nil, nil),
			lbSvc("lb-svc-other-class", nil, new("other")),
			lbSvc("lb-svc-other-pc", map[string]string{LabelAnnotationProxyClass: otherPCName}, nil),
		).
		Build()

	zl := zap.Must(zap.NewDevelopment())
	mapFunc := proxyClassHandlerForSvc(fc, zl.Sugar(), defaultPCName, true)

	for _, tc := range []struct {
		name           string
		proxyClassName string
		expected       []reconcile.Request
	}{
		{
			name:           "default_ProxyClass",
			proxyClassName: defaultPCName,
			expected: []reconcile.Request{
				{NamespacedName: types.NamespacedName{Namespace: "default", Name: "exposed-default"}},
				{NamespacedName: types.NamespacedName{Namespace: "default", Name: "annotated"}},
				{NamespacedName: types.NamespacedName{Namespace: "default", Name: "labelled"}},
				{NamespacedName: types.NamespacedName{Namespace: "foo", Name: "lb-svc"}},
				{NamespacedName: types.NamespacedName{Namespace: "foo", Name: "lb-svc-no-class"}},
			},
		},
		{
			name:           "other_ProxyClass",
			proxyClassName: otherPCName,
			expected: []reconcile.Request{
				{NamespacedName: types.NamespacedName{Namespace: "default", Name: "exposed-other"}},
				{NamespacedName: types.NamespacedName{Namespace: "foo", Name: "lb-svc-other-pc"}},
			},
		},
		{
			name:           "unreferenced_ProxyClass",
			proxyClassName: unreferencedPCName,
			expected:       nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqs := mapFunc(t.Context(), &tsapi.ProxyClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: tc.proxyClassName,
				},
			})
			if len(reqs) != len(tc.expected) {
				t.Fatalf("expected %d requests, got %d: %v", len(tc.expected), len(reqs), reqs)
			}
			for _, expected := range tc.expected {
				if !slices.Contains(reqs, expected) {
					t.Errorf("expected request for Service %q not found in results: %v", expected.Name, reqs)
				}
			}
		})
	}
}
