// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

func TestEgressProxyGroupMoveCleansUpPreviousGroup(t *testing.T) {
	t.Run("move", func(t *testing.T) { testEgressProxyGroupMove(t, false, false) })
	t.Run("retry cleanup", func(t *testing.T) { testEgressProxyGroupMove(t, true, false) })
	t.Run("delete before move", func(t *testing.T) { testEgressProxyGroupMove(t, false, true) })
	t.Run("delete while cleanup pending", func(t *testing.T) { testEgressProxyGroupMove(t, true, true) })
}

func testEgressProxyGroupMove(t *testing.T, retryCleanup, deleteService bool) {
	const operatorNamespace = "operator-ns"
	newGroup := func(name string) (*tsapi.ProxyGroup, *corev1.ConfigMap) {
		return &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name)},
			Spec:       tsapi.ProxyGroupSpec{Type: tsapi.ProxyGroupTypeEgress},
		}, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: pgEgressCMName(name)},
		}
	}
	previous, previousConfig := newGroup("foo")
	destination, destinationConfig := newGroup("bar")
	logger := zap.NewNop()
	clock := tstest.NewClock(tstest.ClockOpts{})
	tsoperator.SetProxyGroupCondition(previous, tsapi.ProxyGroupAvailable, metav1.ConditionTrue, "Available", "Available", previous.Generation, clock, logger.Sugar())
	// The retry case exercises validation clearing EgressSvcConfigured when
	// the destination has no Available condition.
	if !retryCleanup {
		tsoperator.SetProxyGroupCondition(destination, tsapi.ProxyGroupAvailable, metav1.ConditionTrue, "Available", "Available", destination.Generation, clock, logger.Sugar())
	}
	cleanupErr := errors.New("temporary EndpointSlice cleanup failure")
	failCleanup := retryCleanup
	kube := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(previous, previousConfig, destination, destinationConfig).
		WithStatusSubresource(previous, destination).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: clusterIPInterceptor("10.96.0.1"),
			DeleteAllOf: func(ctx context.Context, kube client.WithWatch, obj client.Object, opts ...client.DeleteAllOfOption) error {
				if _, ok := obj.(*discoveryv1.EndpointSlice); ok && failCleanup {
					failCleanup = false
					return cleanupErr
				}
				return kube.DeleteAllOf(ctx, obj, opts...)
			},
		}).
		Build()
	reconciler := &egressSvcsReconciler{
		Client:      kube,
		logger:      logger.Sugar(),
		clock:       clock,
		tsNamespace: operatorNamespace,
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress",
			Namespace: "default",
			UID:       "egress-uid",
			Annotations: map[string]string{
				AnnotationProxyGroup:        previous.Name,
				AnnotationTailnetTargetFQDN: "foo.bar.ts.net.",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "placeholder",
			Ports:        []corev1.ServicePort{{Protocol: corev1.ProtocolTCP, Port: 80}},
		},
	}
	otherService := service.DeepCopy()
	otherService.Name = "other-egress"
	otherService.UID = "other-egress-uid"
	mustCreate(t, kube, otherService)
	expectReconciled(t, reconciler, otherService.Namespace, otherService.Name)
	otherServiceName := findGenNameForEgressSvcResources(t, kube, otherService)

	mustCreate(t, kube, service)
	expectReconciled(t, reconciler, service.Namespace, service.Name)
	previousServiceName := findGenNameForEgressSvcResources(t, kube, service)
	previousService := mustGetClusterIPSvc(t, kube, previousServiceName)
	mustHaveConfigForSvc(t, kube, service, previousService, previousConfig, logger)

	mustUpdate(t, kube, service.Namespace, service.Name, func(s *corev1.Service) {
		s.Annotations[AnnotationProxyGroup] = destination.Name
	})
	if retryCleanup {
		_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(service)})
		if !errors.Is(err, cleanupErr) {
			t.Fatalf("reconcile error = %v, want %v", err, cleanupErr)
		}
		mustGetClusterIPSvc(t, kube, previousServiceName)
		mustGetEndpointSlice(t, kube, previousServiceName+"-ipv4")
	}
	var destinationServiceName string
	if retryCleanup && deleteService {
		if err := kube.Get(t.Context(), client.ObjectKeyFromObject(service), service); err != nil {
			t.Fatal(err)
		}
		destinationServiceName = findGenNameForEgressSvcResources(t, kube, service)
		destinationService := mustGetClusterIPSvc(t, kube, destinationServiceName)
		mustHaveConfigForSvc(t, kube, service, destinationService, destinationConfig, logger)
		mustGetEndpointSlice(t, kube, destinationServiceName+"-ipv4")
	}
	if deleteService {
		if err := kube.Delete(t.Context(), service); err != nil {
			t.Fatal(err)
		}
	}
	expectReconciled(t, reconciler, service.Namespace, service.Name)
	if deleteService {
		expectMissing[corev1.Service](t, kube, service.Namespace, service.Name)
		mustNotHaveConfigForSvc(t, kube, service, destinationConfig)
		if destinationServiceName != "" {
			expectMissing[corev1.Service](t, kube, operatorNamespace, destinationServiceName)
			expectMissing[discoveryv1.EndpointSlice](t, kube, operatorNamespace, destinationServiceName+"-ipv4")
		}
	} else {
		if err := kube.Get(t.Context(), client.ObjectKeyFromObject(service), service); err != nil {
			t.Fatal(err)
		}
		destinationServiceName := findGenNameForEgressSvcResources(t, kube, service)
		destinationService := mustGetClusterIPSvc(t, kube, destinationServiceName)
		wantExternalName := destinationServiceName + "." + operatorNamespace + ".svc.cluster.local"
		if service.Spec.ExternalName != wantExternalName {
			t.Errorf("ExternalName = %q, want %q", service.Spec.ExternalName, wantExternalName)
		}
		wantReason := svcConfiguredReason(service, true, logger.Sugar())
		if cond := tsoperator.GetServiceCondition(service, tsapi.EgressSvcConfigured); cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != wantReason {
			t.Errorf("EgressSvcConfigured = %+v, want True with reason %q", cond, wantReason)
		}
		mustHaveConfigForSvc(t, kube, service, destinationService, destinationConfig, logger)
		expectEqual(t, kube, endpointSlice(destinationServiceName, service, destinationService, discoveryv1.AddressTypeIPv4))
	}

	t.Run("previous config", func(t *testing.T) {
		mustNotHaveConfigForSvc(t, kube, service, previousConfig)
	})
	t.Run("previous service", func(t *testing.T) {
		expectMissing[corev1.Service](t, kube, operatorNamespace, previousServiceName)
	})
	t.Run("previous endpoint slice", func(t *testing.T) {
		expectMissing[discoveryv1.EndpointSlice](t, kube, operatorNamespace, previousServiceName+"-ipv4")
	})
	otherClusterIP := mustGetClusterIPSvc(t, kube, otherServiceName)
	mustHaveConfigForSvc(t, kube, otherService, otherClusterIP, previousConfig, logger)
	mustGetEndpointSlice(t, kube, otherServiceName+"-ipv4")
}
