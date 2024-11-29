// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/AlekSi/pointer"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/egressservices"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
)

func TestTailscaleEgressServices(t *testing.T) {
	pg := &tsapi.ProxyGroup{
		TypeMeta: metav1.TypeMeta{Kind: "ProxyGroup", APIVersion: "tailscale.com/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
			UID:  types.UID("1234-UID"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Replicas: pointer.To[int32](3),
			Type:     tsapi.ProxyGroupTypeEgress,
		},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pgEgressCMName("foo"),
			Namespace: "operator-ns",
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pg, cm).
		WithStatusSubresource(pg).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})

	esr := &egressSvcsReconciler{
		Client:      fc,
		logger:      zl.Sugar(),
		clock:       clock,
		tsNamespace: "operator-ns",
	}
	tailnetTargetFQDN := "foo.bar.ts.net."
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetFQDN: tailnetTargetFQDN,
				AnnotationProxyGroup:        "foo",
			},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Selector:     nil,
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: "TCP",
					Port:     80,
				},
				{
					Name:     "https",
					Protocol: "TCP",
					Port:     443,
				},
			},
		},
	}

	t.Run("proxy_group_not_ready", func(t *testing.T) {
		mustCreate(t, fc, svc)
		expectReconciled(t, esr, "default", "test")
		// Service should have EgressSvcValid condition set to Unknown.
		svc.Status.Conditions = []metav1.Condition{condition(tsapi.EgressSvcValid, metav1.ConditionUnknown, reasonProxyGroupNotReady, reasonProxyGroupNotReady, clock)}
		expectEqual(t, fc, svc, nil)
	})

	t.Run("proxy_group_ready", func(t *testing.T) {
		mustUpdateStatus(t, fc, "", "foo", func(pg *tsapi.ProxyGroup) {
			pg.Status.Conditions = []metav1.Condition{
				condition(tsapi.ProxyGroupReady, metav1.ConditionTrue, "", "", clock),
			}
		})
		expectReconciled(t, esr, "default", "test")
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
	})
	t.Run("service_retain_one_unnamed_port", func(t *testing.T) {
		svc.Spec.Ports = []corev1.ServicePort{{Protocol: "TCP", Port: 80}}
		mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
			s.Spec.Ports = svc.Spec.Ports
		})
		expectReconciled(t, esr, "default", "test")
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
	})
	t.Run("service_add_two_named_ports", func(t *testing.T) {
		svc.Spec.Ports = []corev1.ServicePort{{Protocol: "TCP", Port: 80, Name: "http"}, {Protocol: "TCP", Port: 443, Name: "https"}}
		mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
			s.Spec.Ports = svc.Spec.Ports
		})
		expectReconciled(t, esr, "default", "test")
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
	})
	t.Run("service_add_udp_port", func(t *testing.T) {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Port: 53, Protocol: "UDP", Name: "dns"})
		mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
			s.Spec.Ports = svc.Spec.Ports
		})
		expectReconciled(t, esr, "default", "test")
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
	})
	t.Run("service_change_protocol", func(t *testing.T) {
		svc.Spec.Ports = []corev1.ServicePort{{Protocol: "TCP", Port: 80, Name: "http"}, {Protocol: "TCP", Port: 443, Name: "https"}, {Port: 53, Protocol: "TCP", Name: "tcp_dns"}}
		mustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
			s.Spec.Ports = svc.Spec.Ports
		})
		expectReconciled(t, esr, "default", "test")
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
	})

	t.Run("delete_external_name_service", func(t *testing.T) {
		name := findGenNameForEgressSvcResources(t, fc, svc)
		if err := fc.Delete(context.Background(), svc); err != nil {
			t.Fatalf("error deleting ExternalName Service: %v", err)
		}
		expectReconciled(t, esr, "default", "test")
		// Verify that ClusterIP Service and EndpointSlice have been deleted.
		expectMissing[corev1.Service](t, fc, "operator-ns", name)
		expectMissing[discoveryv1.EndpointSlice](t, fc, "operator-ns", fmt.Sprintf("%s-ipv4", name))
		// Verify that service config has been deleted from the ConfigMap.
		mustNotHaveConfigForSvc(t, fc, svc, cm)
	})
}

func validateReadyService(t *testing.T, fc client.WithWatch, esr *egressSvcsReconciler, svc *corev1.Service, clock *tstest.Clock, zl *zap.Logger, cm *corev1.ConfigMap) {
	expectReconciled(t, esr, "default", "test")
	// Verify that a ClusterIP Service has been created.
	name := findGenNameForEgressSvcResources(t, fc, svc)
	expectEqual(t, fc, clusterIPSvc(name, svc), removeTargetPortsFromSvc)
	clusterSvc := mustGetClusterIPSvc(t, fc, name)
	// Verify that an EndpointSlice has been created.
	expectEqual(t, fc, endpointSlice(name, svc, clusterSvc), nil)
	// Verify that ConfigMap contains configuration for the new egress service.
	mustHaveConfigForSvc(t, fc, svc, clusterSvc, cm)
	r := svcConfiguredReason(svc, true, zl.Sugar())
	// Verify that the user-created ExternalName Service has Configured set to true and ExternalName pointing to the
	// CluterIP Service.
	svc.Status.Conditions = []metav1.Condition{
		condition(tsapi.EgressSvcValid, metav1.ConditionTrue, "EgressSvcValid", "EgressSvcValid", clock),
		condition(tsapi.EgressSvcConfigured, metav1.ConditionTrue, r, r, clock),
	}
	svc.ObjectMeta.Finalizers = []string{"tailscale.com/finalizer"}
	svc.Spec.ExternalName = fmt.Sprintf("%s.operator-ns.svc.cluster.local", name)
	expectEqual(t, fc, svc, nil)

}

func condition(typ tsapi.ConditionType, st metav1.ConditionStatus, r, msg string, clock tstime.Clock) metav1.Condition {
	return metav1.Condition{
		Type:               string(typ),
		Status:             st,
		LastTransitionTime: conditionTime(clock),
		Reason:             r,
		Message:            msg,
	}
}

func findGenNameForEgressSvcResources(t *testing.T, client client.Client, svc *corev1.Service) string {
	t.Helper()
	labels := egressSvcChildResourceLabels(svc)
	s, err := getSingleObject[corev1.Service](context.Background(), client, "operator-ns", labels)
	if err != nil {
		t.Fatalf("finding ClusterIP Service for ExternalName Service %s: %v", svc.Name, err)
	}
	if s == nil {
		t.Fatalf("no ClusterIP Service found for ExternalName Service %q", svc.Name)
	}
	return s.GetName()
}

func clusterIPSvc(name string, extNSvc *corev1.Service) *corev1.Service {
	labels := egressSvcChildResourceLabels(extNSvc)
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:         name,
			Namespace:    "operator-ns",
			GenerateName: fmt.Sprintf("ts-%s-", extNSvc.Name),
			Labels:       labels,
		},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeClusterIP,
			Ports: extNSvc.Spec.Ports,
		},
	}
}

func mustGetClusterIPSvc(t *testing.T, cl client.Client, name string) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "operator-ns",
		},
	}
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(svc), svc); err != nil {
		t.Fatalf("error retrieving Service")
	}
	return svc
}

func endpointSlice(name string, extNSvc, clusterIPSvc *corev1.Service) *discoveryv1.EndpointSlice {
	labels := egressSvcChildResourceLabels(extNSvc)
	labels[discoveryv1.LabelManagedBy] = "tailscale.com"
	labels[discoveryv1.LabelServiceName] = name
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-ipv4", name),
			Namespace: "operator-ns",
			Labels:    labels,
		},
		Ports:       portsForEndpointSlice(clusterIPSvc),
		AddressType: discoveryv1.AddressTypeIPv4,
	}
}

func portsForEndpointSlice(svc *corev1.Service) []discoveryv1.EndpointPort {
	ports := make([]discoveryv1.EndpointPort, 0)
	for _, p := range svc.Spec.Ports {
		ports = append(ports, discoveryv1.EndpointPort{
			Name:     &p.Name,
			Protocol: &p.Protocol,
			Port:     pointer.ToInt32(p.TargetPort.IntVal),
		})
	}
	return ports
}

func mustHaveConfigForSvc(t *testing.T, cl client.Client, extNSvc, clusterIPSvc *corev1.Service, cm *corev1.ConfigMap) {
	t.Helper()
	wantsCfg := egressSvcCfg(extNSvc, clusterIPSvc)
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(cm), cm); err != nil {
		t.Fatalf("Error retrieving ConfigMap: %v", err)
	}
	name := tailnetSvcName(extNSvc)
	gotCfg := configFromCM(t, cm, name)
	if gotCfg == nil {
		t.Fatalf("No config found for service %q", name)
	}
	if diff := cmp.Diff(*gotCfg, wantsCfg); diff != "" {
		t.Fatalf("unexpected config for service %q (-got +want):\n%s", name, diff)
	}
}

func mustNotHaveConfigForSvc(t *testing.T, cl client.Client, extNSvc *corev1.Service, cm *corev1.ConfigMap) {
	t.Helper()
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(cm), cm); err != nil {
		t.Fatalf("Error retrieving ConfigMap: %v", err)
	}
	name := tailnetSvcName(extNSvc)
	gotCfg := configFromCM(t, cm, name)
	if gotCfg != nil {
		t.Fatalf("Config  %#+v for service %q found when it should not be present", gotCfg, name)
	}
}

func configFromCM(t *testing.T, cm *corev1.ConfigMap, svcName string) *egressservices.Config {
	t.Helper()
	cfgBs, ok := cm.BinaryData[egressservices.KeyEgressServices]
	if !ok {
		return nil
	}
	cfgs := &egressservices.Configs{}
	if err := json.Unmarshal(cfgBs, cfgs); err != nil {
		t.Fatalf("error unmarshalling config: %v", err)
	}
	cfg, ok := (*cfgs)[svcName]
	if ok {
		return &cfg
	}
	return nil
}
