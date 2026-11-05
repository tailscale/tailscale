// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package egress_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/AlekSi/pointer"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/egress"
	"tailscale.com/k8s-operator/reconciler/reconcilertest"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/util/mak"
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
			Name:      reconciler.ProxyGroupEgressConfigMapName("foo"),
			Namespace: "operator-ns",
		},
	}
	fc := reconcilertest.NewClientBuilder().
		WithObjects(pg, cm).
		WithStatusSubresource(pg).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: clusterIPInterceptor("10.96.0.1"),
		}).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})

	esr := egress.NewReconciler(egress.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: "operator-ns",
		Logger:             zl.Sugar(),
		Clock:              clock,
	})
	tailnetTargetFQDN := "foo.bar.ts.net."
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				reconciler.AnnotationTailnetTargetFQDN: tailnetTargetFQDN,
				reconciler.AnnotationProxyGroup:        "foo",
			},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Selector:     nil,
			Ports: []corev1.ServicePort{
				{
					Protocol: "TCP",
					Port:     80,
				},
			},
		},
	}

	t.Run("service_one_unnamed_port", func(t *testing.T) {
		reconcilertest.MustCreate(t, fc, svc)
		reconcilertest.ExpectReconciled(t, esr, "default", "test")
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
	})
	t.Run("service_add_two_named_ports", func(t *testing.T) {
		svc.Spec.Ports = []corev1.ServicePort{{Protocol: "TCP", Port: 80, Name: "http"}, {Protocol: "TCP", Port: 443, Name: "https"}}
		reconcilertest.MustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
			s.Spec.Ports = svc.Spec.Ports
		})
		reconcilertest.ExpectReconciled(t, esr, "default", "test")
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
	})
	t.Run("service_add_udp_port", func(t *testing.T) {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Port: 53, Protocol: "UDP", Name: "dns"})
		reconcilertest.MustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
			s.Spec.Ports = svc.Spec.Ports
		})
		reconcilertest.ExpectReconciled(t, esr, "default", "test")
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
	})
	t.Run("service_change_protocol", func(t *testing.T) {
		svc.Spec.Ports = []corev1.ServicePort{{Protocol: "TCP", Port: 80, Name: "http"}, {Protocol: "TCP", Port: 443, Name: "https"}, {Port: 53, Protocol: "TCP", Name: "tcp_dns"}}
		reconcilertest.MustUpdate(t, fc, "default", "test", func(s *corev1.Service) {
			s.Spec.Ports = svc.Spec.Ports
		})
		reconcilertest.ExpectReconciled(t, esr, "default", "test")
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
	})

	t.Run("endpointslice_deletion_recovery", func(t *testing.T) {
		name := findGenNameForEgressSvcResources(t, fc, svc)
		epsName := fmt.Sprintf("%s-ipv4", name)
		// Delete the EndpointSlice and verify it is recreated.
		eps := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      epsName,
				Namespace: "operator-ns",
			},
		}
		if err := fc.Delete(t.Context(), eps); err != nil {
			t.Fatalf("error deleting EndpointSlice: %v", err)
		}
		reconcilertest.ExpectMissing[discoveryv1.EndpointSlice](t, fc, "operator-ns", epsName)
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
	})

	t.Run("delete_external_name_service", func(t *testing.T) {
		name := findGenNameForEgressSvcResources(t, fc, svc)
		if err := fc.Delete(context.Background(), svc); err != nil {
			t.Fatalf("error deleting ExternalName Service: %v", err)
		}
		reconcilertest.ExpectReconciled(t, esr, "default", "test")
		// Verify that ClusterIP Service and EndpointSlice have been deleted.
		reconcilertest.ExpectMissing[corev1.Service](t, fc, "operator-ns", name)
		reconcilertest.ExpectMissing[discoveryv1.EndpointSlice](t, fc, "operator-ns", fmt.Sprintf("%s-ipv4", name))
		// Verify that service config has been deleted from the ConfigMap.
		mustNotHaveConfigForSvc(t, fc, svc, cm)
	})
}

func validateReadyService(t *testing.T, fc client.WithWatch, esr *egress.Reconciler, svc *corev1.Service, clock *tstest.Clock, zl *zap.Logger, cm *corev1.ConfigMap) {
	reconcilertest.ExpectReconciled(t, esr, "default", "test")
	// Verify that a ClusterIP Service has been created.
	name := findGenNameForEgressSvcResources(t, fc, svc)
	reconcilertest.ExpectEqual(t, fc, clusterIPSvc(name, svc), removeTargetPortsFromSvc, removeClusterIPsFromSvc)
	clusterSvc := mustGetClusterIPSvc(t, fc, name)
	// Verify that an EndpointSlice has been created.
	reconcilertest.ExpectEqual(t, fc, endpointSlice(name, svc, clusterSvc, discoveryv1.AddressTypeIPv4))
	// Verify that ConfigMap contains configuration for the new egress service.
	mustHaveConfigForSvc(t, fc, svc, clusterSvc, cm, zl)
	r := configuredReason(t, svc)
	// Verify that the user-created ExternalName Service has Configured set to true and ExternalName pointing to the
	// CluterIP Service.
	svc.Status.Conditions = []metav1.Condition{
		condition(tsapi.EgressSvcValid, metav1.ConditionTrue, "EgressSvcValid", "EgressSvcValid", clock),
		condition(tsapi.EgressSvcConfigured, metav1.ConditionTrue, r, r, clock),
	}
	svc.ObjectMeta.Finalizers = []string{"tailscale.com/finalizer"}
	svc.Spec.ExternalName = fmt.Sprintf("%s.operator-ns.svc.cluster.local", name)
	reconcilertest.ExpectEqual(t, fc, svc)

}

func condition(typ tsapi.ConditionType, st metav1.ConditionStatus, r, msg string, clock tstime.Clock) metav1.Condition {
	return metav1.Condition{
		Type:               string(typ),
		Status:             st,
		LastTransitionTime: metav1.NewTime(clock.Now().Truncate(time.Second)),
		Reason:             r,
		Message:            msg,
	}
}

func findGenNameForEgressSvcResources(t *testing.T, client client.Client, svc *corev1.Service) string {
	t.Helper()
	labels := childResourceLabels(svc)
	s, err := reconciler.GetSingleObject[corev1.Service](context.Background(), client, "operator-ns", labels)
	if err != nil {
		t.Fatalf("finding ClusterIP Service for ExternalName Service %s: %v", svc.Name, err)
	}
	if s == nil {
		t.Fatalf("no ClusterIP Service found for ExternalName Service %q", svc.Name)
	}
	return s.GetName()
}

func clusterIPSvc(name string, extNSvc *corev1.Service) *corev1.Service {
	labels := childResourceLabels(extNSvc)
	ports := make([]corev1.ServicePort, len(extNSvc.Spec.Ports))
	for i, port := range extNSvc.Spec.Ports {
		ports[i] = corev1.ServicePort{ // Copy the port to avoid modifying the original.
			Name:     port.Name,
			Port:     port.Port,
			Protocol: port.Protocol,
		}
		if port.Name == "" {
			ports[i].Name = "tailscale-unnamed"
		}
	}
	ports = append(ports, corev1.ServicePort{
		Name:       "tailscale-health-check",
		Port:       9002,
		TargetPort: intstr.FromInt(9002),
		Protocol:   "TCP",
	})
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:         name,
			Namespace:    "operator-ns",
			GenerateName: fmt.Sprintf("ts-%s-", extNSvc.Name),
			Labels:       labels,
		},
		Spec: corev1.ServiceSpec{
			Type:           corev1.ServiceTypeClusterIP,
			IPFamilyPolicy: new(corev1.IPFamilyPolicyPreferDualStack),
			Ports:          ports,
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

func endpointSlice(name string, extNSvc, clusterIPSvc *corev1.Service, addrType discoveryv1.AddressType) *discoveryv1.EndpointSlice {
	labels := childResourceLabels(extNSvc)
	labels[discoveryv1.LabelManagedBy] = "tailscale.com"
	labels[discoveryv1.LabelServiceName] = name
	suffix := "ipv4"
	if addrType == discoveryv1.AddressTypeIPv6 {
		suffix = "ipv6"
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", name, suffix),
			Namespace: "operator-ns",
			Labels:    labels,
		},
		Ports:       portsForEndpointSlice(clusterIPSvc),
		AddressType: addrType,
	}
}

func portsForEndpointSlice(svc *corev1.Service) []discoveryv1.EndpointPort {
	ports := make([]discoveryv1.EndpointPort, 0)
	for _, p := range svc.Spec.Ports {
		ports = append(ports, discoveryv1.EndpointPort{
			Name:     &p.Name,
			Protocol: &p.Protocol,
			Port:     new(p.TargetPort.IntVal),
		})
	}
	return ports
}

func mustHaveConfigForSvc(t *testing.T, cl client.Client, extNSvc, clusterIPSvc *corev1.Service, cm *corev1.ConfigMap, lg *zap.Logger) {
	t.Helper()
	wantsCfg := egressConfig(extNSvc, clusterIPSvc)
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
	cfgs := egressservices.Configs{}
	if err := json.Unmarshal(cfgBs, &cfgs); err != nil {
		t.Fatalf("error unmarshalling config: %v", err)
	}
	cfg, ok := cfgs[svcName]
	if ok {
		return &cfg
	}
	return nil
}

func TestTailscaleEgressServicesDualStack(t *testing.T) {
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
			Name:      reconciler.ProxyGroupEgressConfigMapName("foo"),
			Namespace: "operator-ns",
		},
	}
	fc := reconcilertest.NewClientBuilder().
		WithObjects(pg, cm).
		WithStatusSubresource(pg).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: clusterIPInterceptor("10.96.0.1", "fd00::1"),
		}).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})

	esr := egress.NewReconciler(egress.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: "operator-ns",
		Logger:             zl.Sugar(),
		Clock:              clock,
	})
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				reconciler.AnnotationTailnetTargetFQDN: "foo.bar.ts.net.",
				reconciler.AnnotationProxyGroup:        "foo",
			},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Selector:     nil,
			Ports: []corev1.ServicePort{
				{
					Protocol: "TCP",
					Port:     80,
				},
			},
		},
	}

	t.Run("dual_stack_creates_both_endpoint_slices", func(t *testing.T) {
		reconcilertest.MustCreate(t, fc, svc)
		reconcilertest.ExpectReconciled(t, esr, "default", "test")
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
		// Also verify the IPv6 EndpointSlice was created.
		name := findGenNameForEgressSvcResources(t, fc, svc)
		clusterSvc := mustGetClusterIPSvc(t, fc, name)
		reconcilertest.ExpectEqual(t, fc, endpointSlice(name, svc, clusterSvc, discoveryv1.AddressTypeIPv6))
	})

	t.Run("dual_stack_endpointslice_deletion_recovery", func(t *testing.T) {
		name := findGenNameForEgressSvcResources(t, fc, svc)
		// Delete both IPv4 and IPv6 EndpointSlices.
		for _, suffix := range []string{"ipv4", "ipv6"} {
			epsName := fmt.Sprintf("%s-%s", name, suffix)
			eps := &discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      epsName,
					Namespace: "operator-ns",
				},
			}
			if err := fc.Delete(t.Context(), eps); err != nil {
				t.Fatalf("error deleting EndpointSlice %s: %v", epsName, err)
			}
			reconcilertest.ExpectMissing[discoveryv1.EndpointSlice](t, fc, "operator-ns", epsName)
		}
		// Reconcile should recreate both.
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
		clusterSvc := mustGetClusterIPSvc(t, fc, name)
		reconcilertest.ExpectEqual(t, fc, endpointSlice(name, svc, clusterSvc, discoveryv1.AddressTypeIPv6))
	})

	t.Run("dual_stack_single_endpointslice_deletion_recovery", func(t *testing.T) {
		name := findGenNameForEgressSvcResources(t, fc, svc)
		// Delete only the IPv6 EndpointSlice.
		epsName := fmt.Sprintf("%s-ipv6", name)
		eps := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      epsName,
				Namespace: "operator-ns",
			},
		}
		if err := fc.Delete(t.Context(), eps); err != nil {
			t.Fatalf("error deleting EndpointSlice %s: %v", epsName, err)
		}
		reconcilertest.ExpectMissing[discoveryv1.EndpointSlice](t, fc, "operator-ns", epsName)
		// Reconcile should recreate the missing IPv6 EndpointSlice while leaving
		// the IPv4 one untouched.
		validateReadyService(t, fc, esr, svc, clock, zl, cm)
		clusterSvc := mustGetClusterIPSvc(t, fc, name)
		reconcilertest.ExpectEqual(t, fc, endpointSlice(name, svc, clusterSvc, discoveryv1.AddressTypeIPv6))
		reconcilertest.ExpectEqual(t, fc, endpointSlice(name, svc, clusterSvc, discoveryv1.AddressTypeIPv4))
	})

	t.Run("delete_dual_stack_service", func(t *testing.T) {
		name := findGenNameForEgressSvcResources(t, fc, svc)
		if err := fc.Delete(context.Background(), svc); err != nil {
			t.Fatalf("error deleting ExternalName Service: %v", err)
		}
		reconcilertest.ExpectReconciled(t, esr, "default", "test")
		reconcilertest.ExpectMissing[corev1.Service](t, fc, "operator-ns", name)
		reconcilertest.ExpectMissing[discoveryv1.EndpointSlice](t, fc, "operator-ns", fmt.Sprintf("%s-ipv4", name))
		reconcilertest.ExpectMissing[discoveryv1.EndpointSlice](t, fc, "operator-ns", fmt.Sprintf("%s-ipv6", name))
		mustNotHaveConfigForSvc(t, fc, svc, cm)
	})
}

// TestEgressServiceGatedProvision verifies that egress provisioning is gated on
// up-to-date configuration. If an expected EndpointSlice is
// missing, provision must recreate it, without depending on a configuration change
// and without reshuffling the ClusterIP Service ports.
func TestEgressServiceGatedProvision(t *testing.T) {
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
			Name:      reconciler.ProxyGroupEgressConfigMapName("foo"),
			Namespace: "operator-ns",
		},
	}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	clock := tstest.NewClock(tstest.ClockOpts{})
	// Mark the ProxyGroup Available so validateClusterResources does not strip
	// the EgressSvcConfigured condition.
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, metav1.ConditionTrue, "foo", "foo", pg.Generation, clock, zl.Sugar())

	fc := reconcilertest.NewClientBuilder().
		WithObjects(pg, cm).
		WithStatusSubresource(pg, &corev1.Service{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: clusterIPInterceptor("10.96.0.1"),
		}).
		Build()

	esr := egress.NewReconciler(egress.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: "operator-ns",
		Logger:             zl.Sugar(),
		Clock:              clock,
	})
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				reconciler.AnnotationTailnetTargetFQDN: "foo.bar.ts.net.",
				reconciler.AnnotationProxyGroup:        "foo",
			},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Ports: []corev1.ServicePort{
				{Protocol: "TCP", Port: 80},
			},
		},
	}
	reconcilertest.MustCreate(t, fc, svc)

	// First reconcile: provisions the single-stack (IPv4) EndpointSlice and sets
	// EgressSvcConfigured=True.
	reconcilertest.ExpectReconciled(t, esr, "default", "test")
	name := findGenNameForEgressSvcResources(t, fc, svc)
	v4Name := fmt.Sprintf("%s-ipv4", name)
	v6Name := fmt.Sprintf("%s-ipv6", name)
	reconcilertest.ExpectMissing[discoveryv1.EndpointSlice](t, fc, "operator-ns", v6Name)
	gotSvc := &corev1.Service{}
	if err := fc.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: "test"}, gotSvc); err != nil {
		t.Fatalf("getting Service: %v", err)
	}
	if cond := tsoperator.GetServiceCondition(gotSvc, tsapi.EgressSvcConfigured); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("EgressSvcConfigured condition not True after first reconcile: %+v", cond)
	}

	// Second reconcile: the service is up to date (same single family), so the
	// gate must skip provision and not rewrite the IPv4 EndpointSlice.
	v4Before := mustGetEndpointSlice(t, fc, v4Name)
	reconcilertest.ExpectReconciled(t, esr, "default", "test")
	v4After := mustGetEndpointSlice(t, fc, v4Name)
	if v4Before.ResourceVersion != v4After.ResourceVersion {
		t.Errorf("IPv4 EndpointSlice was rewritten on a no-op reconcile: resourceVersion %s -> %s", v4Before.ResourceVersion, v4After.ResourceVersion)
	}

	// If an expected EndpointSlice is missing while the config is up to date, the
	// missingEndpointSliceFamilies check must flip the gate false so provision reruns
	// and recreates the slice, without reshuffling the ClusterIP Service ports. The
	// check looks slices up by name, so an orphaned slice with the same labels must
	// not satisfy it.
	clusterPortsBefore := mustGetClusterIPSvc(t, fc, name).Spec.Ports
	reconcilertest.MustCreate(t, fc, endpointSlice("ts-foo-orphan", svc, mustGetClusterIPSvc(t, fc, name), discoveryv1.AddressTypeIPv4))
	if err := fc.Delete(t.Context(), &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: v4Name, Namespace: "operator-ns"},
	}); err != nil {
		t.Fatalf("deleting EndpointSlice: %v", err)
	}
	reconcilertest.ExpectMissing[discoveryv1.EndpointSlice](t, fc, "operator-ns", v4Name)
	reconcilertest.ExpectReconciled(t, esr, "default", "test")
	clusterSvc := mustGetClusterIPSvc(t, fc, name)
	reconcilertest.ExpectEqual(t, fc, endpointSlice(name, svc, clusterSvc, discoveryv1.AddressTypeIPv4))
	if diff := cmp.Diff(clusterSvc.Spec.Ports, clusterPortsBefore); diff != "" {
		t.Errorf("ClusterIP Service ports changed after reprovision (-got +want):\n%s", diff)
	}
}

func mustGetEndpointSlice(t *testing.T, cl client.Client, name string) *discoveryv1.EndpointSlice {
	t.Helper()
	eps := &discoveryv1.EndpointSlice{}
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: "operator-ns", Name: name}, eps); err != nil {
		t.Fatalf("getting EndpointSlice %s: %v", name, err)
	}
	return eps
}

// clusterIPInterceptor returns an interceptor.Funcs Create function that
// simulates the API server assigning ClusterIPs to ClusterIP Services.
// This is required because the reconciler iterates ClusterIPs to create
// per-family EndpointSlices but the fake client does not assign ClusterIPs.
func clusterIPInterceptor(clusterIPs ...string) func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
	return func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if svc, ok := obj.(*corev1.Service); ok && svc.Spec.Type == corev1.ServiceTypeClusterIP {
			svc.Spec.ClusterIPs = clusterIPs
			svc.Spec.ClusterIP = clusterIPs[0]
		}
		return c.Create(ctx, obj, opts...)
	}
}

func removeTargetPortsFromSvc(svc *corev1.Service) {
	newPorts := make([]corev1.ServicePort, 0)
	for _, p := range svc.Spec.Ports {
		newPorts = append(newPorts, corev1.ServicePort{Protocol: p.Protocol, Port: p.Port, Name: p.Name})
	}
	svc.Spec.Ports = newPorts
}

func removeClusterIPsFromSvc(svc *corev1.Service) {
	svc.Spec.ClusterIP = ""
	svc.Spec.ClusterIPs = nil
}

// childResourceLabels returns the labels that the Reconciler sets on the ClusterIP Service and EndpointSlices that it
// creates for the egress Service svc.
func childResourceLabels(svc *corev1.Service) map[string]string {
	return map[string]string{
		kubetypes.LabelManaged:          "true",
		reconciler.LabelParentType:      "svc",
		reconciler.LabelParentName:      svc.Name,
		reconciler.LabelParentNamespace: svc.Namespace,
		reconciler.LabelProxyGroup:      svc.Annotations[reconciler.AnnotationProxyGroup],
		"tailscale.com/svc-type":        "egress",
	}
}

// epsLabels returns the labels that the Reconciler sets on the EndpointSlices that it creates for the egress Service
// extNSvc and its ClusterIP Service.
func epsLabels(extNSvc, clusterIPSvc *corev1.Service) map[string]string {
	labels := childResourceLabels(extNSvc)
	labels[discoveryv1.LabelServiceName] = clusterIPSvc.Name
	labels[discoveryv1.LabelManagedBy] = "tailscale.com"
	return labels
}

// tailnetSvcName returns the key of the egress service config for svc in the egress ConfigMap.
func tailnetSvcName(svc *corev1.Service) string {
	return fmt.Sprintf("%s-%s", svc.Namespace, svc.Name)
}

// tailnetTarget returns the tailnet target that the annotations of svc define.
func tailnetTarget(svc *corev1.Service) egressservices.TailnetTarget {
	if fqdn := svc.Annotations[reconciler.AnnotationTailnetTargetFQDN]; fqdn != "" {
		return egressservices.TailnetTarget{FQDN: fqdn}
	}
	return egressservices.TailnetTarget{IP: svc.Annotations[reconciler.AnnotationTailnetTargetIP]}
}

// configuredReason returns the reason of the EgressSvcConfigured condition once the Reconciler has configured svc. The
// reason holds a SHA-256 hash of the configuration, so a change to the ports, the target or the ProxyGroup changes it.
func configuredReason(t *testing.T, svc *corev1.Service) string {
	t.Helper()
	pg := svc.Annotations[reconciler.AnnotationProxyGroup]
	bs, err := json.Marshal(struct {
		Ports         []corev1.ServicePort         `json:"ports"`
		TailnetTarget egressservices.TailnetTarget `json:"tailnetTarget"`
		ProxyGroup    string                       `json:"proxyGroup"`
	}{svc.Spec.Ports, tailnetTarget(svc), pg})
	if err != nil {
		t.Fatalf("marshalling config: %v", err)
	}
	return fmt.Sprintf("ConfiguredFor:ProxyGroup:%s:Config:%x", pg, sha256.Sum256(bs))
}

// egressConfig returns the egress service config that the Reconciler writes for extNSvc and its ClusterIP Service.
func egressConfig(extNSvc, clusterIPSvc *corev1.Service) egressservices.Config {
	cfg := egressservices.Config{TailnetTarget: tailnetTarget(extNSvc)}
	for _, p := range clusterIPSvc.Spec.Ports {
		if p.Name == "tailscale-health-check" {
			cfg.HealthCheckEndpoint = fmt.Sprintf("http://%s.%s.svc.cluster.local:%d/healthz", clusterIPSvc.Name, clusterIPSvc.Namespace, p.Port)
			continue
		}
		mak.Set(&cfg.Ports, egressservices.PortMap{
			Protocol:   string(p.Protocol),
			MatchPort:  uint16(p.TargetPort.IntVal),
			TargetPort: uint16(p.Port),
		}, struct{}{})
	}
	return cfg
}
