// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
)

func TestDNSRecordsReconciler(t *testing.T) {
	// Preconfigure a cluster with a DNSConfig
	dnsConfig := &tsapi.DNSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		TypeMeta: metav1.TypeMeta{Kind: "DNSConfig"},
		Spec: tsapi.DNSConfigSpec{
			Nameserver: &tsapi.Nameserver{},
		}}
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ts-ingress",
			Namespace: "test",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: []networkingv1.IngressLoadBalancerIngress{{
					Hostname: "cluster.ingress.ts.net"}},
			},
		},
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "dnsrecords", Namespace: "tailscale"}}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(cm).
		WithObjects(dnsConfig).
		WithObjects(ing).
		WithStatusSubresource(dnsConfig, ing).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	// Set the ready condition of the DNSConfig
	mustUpdateStatus(t, fc, "", "test", func(c *tsapi.DNSConfig) {
		operatorutils.SetDNSConfigCondition(c, tsapi.NameserverReady, metav1.ConditionTrue, reasonNameserverCreated, reasonNameserverCreated, 0, cl, zl.Sugar())
	})
	dnsRR := &dnsRecordsReconciler{
		Client:      fc,
		logger:      zl.Sugar(),
		tsNamespace: "tailscale",
	}

	// 1. DNS record is created for an egress proxy configured via
	// tailscale.com/tailnet-fqdn annotation
	egressSvcFQDN := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "egress-fqdn",
			Namespace:   "test",
			Annotations: map[string]string{"tailscale.com/tailnet-fqdn": "foo.bar.ts.net"},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "unused",
			Type:         corev1.ServiceTypeExternalName,
		},
	}
	headlessForEgressSvcFQDN := headlessSvcForParent(egressSvcFQDN, "svc") // create the proxy headless Service
	ep := endpointSliceForService(headlessForEgressSvcFQDN, "10.9.8.7", discoveryv1.AddressTypeIPv4)
	epv6 := endpointSliceForService(headlessForEgressSvcFQDN, "2600:1900:4011:161:0:d:0:d", discoveryv1.AddressTypeIPv6)

	mustCreate(t, fc, egressSvcFQDN)
	mustCreate(t, fc, headlessForEgressSvcFQDN)
	mustCreate(t, fc, ep)
	mustCreate(t, fc, epv6)
	expectReconciled(t, dnsRR, "tailscale", "egress-fqdn") // dns-records-reconciler reconcile the headless Service
	// ConfigMap should now have a record for foo.bar.ts.net -> 10.8.8.7
	wantHosts := map[string][]string{"foo.bar.ts.net": {"10.9.8.7"}}
	wantHostsIPv6 := map[string][]string{"foo.bar.ts.net": {"2600:1900:4011:161:0:d:0:d"}}
	expectHostsRecordsWithIPv6(t, fc, wantHosts, wantHostsIPv6)

	// 2. DNS record is updated if tailscale.com/tailnet-fqdn annotation's
	// value changes
	mustUpdate(t, fc, "test", "egress-fqdn", func(svc *corev1.Service) {
		svc.Annotations["tailscale.com/tailnet-fqdn"] = "baz.bar.ts.net"
	})
	expectReconciled(t, dnsRR, "tailscale", "egress-fqdn") // dns-records-reconciler reconcile the headless Service
	wantHosts = map[string][]string{"baz.bar.ts.net": {"10.9.8.7"}}
	expectHostsRecords(t, fc, wantHosts)

	// 3. DNS record is updated if the IP address of the proxy Pod changes.
	ep = endpointSliceForService(headlessForEgressSvcFQDN, "10.6.5.4", discoveryv1.AddressTypeIPv4)
	mustUpdate(t, fc, ep.Namespace, ep.Name, func(ep *discoveryv1.EndpointSlice) {
		ep.Endpoints[0].Addresses = []string{"10.6.5.4"}
	})
	expectReconciled(t, dnsRR, "tailscale", "egress-fqdn") // dns-records-reconciler reconcile the headless Service
	wantHosts = map[string][]string{"baz.bar.ts.net": {"10.6.5.4"}}
	expectHostsRecords(t, fc, wantHosts)

	// 4. DNS record is created for an ingress proxy configured via Ingress
	headlessForIngress := headlessSvcForParent(ing, "ingress")
	ep = endpointSliceForService(headlessForIngress, "10.9.8.7", discoveryv1.AddressTypeIPv4)
	mustCreate(t, fc, headlessForIngress)
	mustCreate(t, fc, ep)
	expectReconciled(t, dnsRR, "tailscale", "ts-ingress") // dns-records-reconciler should reconcile the headless Service
	wantHosts["cluster.ingress.ts.net"] = []string{"10.9.8.7"}
	expectHostsRecords(t, fc, wantHosts)

	// 5. DNS records are updated if Ingress's MagicDNS name changes (i.e users changed spec.tls.hosts[0])
	t.Log("test case 5")
	mustUpdateStatus(t, fc, "test", "ts-ingress", func(ing *networkingv1.Ingress) {
		ing.Status.LoadBalancer.Ingress[0].Hostname = "another.ingress.ts.net"
	})
	expectReconciled(t, dnsRR, "tailscale", "ts-ingress") // dns-records-reconciler should reconcile the headless Service
	delete(wantHosts, "cluster.ingress.ts.net")
	wantHosts["another.ingress.ts.net"] = []string{"10.9.8.7"}
	expectHostsRecords(t, fc, wantHosts)

	// 6. DNS records are updated if Ingress proxy's Pod IP changes
	mustUpdate(t, fc, ep.Namespace, ep.Name, func(ep *discoveryv1.EndpointSlice) {
		ep.Endpoints[0].Addresses = []string{"7.8.9.10"}
	})
	expectReconciled(t, dnsRR, "tailscale", "ts-ingress")
	wantHosts["another.ingress.ts.net"] = []string{"7.8.9.10"}
	expectHostsRecords(t, fc, wantHosts)

	// 7. A not-ready Endpoint is removed from DNS config.
	mustUpdate(t, fc, ep.Namespace, ep.Name, func(ep *discoveryv1.EndpointSlice) {
		ep.Endpoints[0].Conditions.Ready = ptr.To(false)
		ep.Endpoints = append(ep.Endpoints, discoveryv1.Endpoint{
			Addresses: []string{"1.2.3.4"},
		})
	})
	expectReconciled(t, dnsRR, "tailscale", "ts-ingress")
	wantHosts["another.ingress.ts.net"] = []string{"1.2.3.4"}
	expectHostsRecords(t, fc, wantHosts)

	// 8. DNS record is created for ProxyGroup egress using ClusterIP Service IP instead of Pod IPs
	t.Log("test case 8: ProxyGroup egress")

	// Create the parent ExternalName service with tailnet-fqdn annotation
	parentEgressSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "external-service",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationTailnetTargetFQDN: "external-service.example.ts.net",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "unused",
		},
	}
	mustCreate(t, fc, parentEgressSvc)

	proxyGroupEgressSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ts-proxygroup-egress-abcd1",
			Namespace: "tailscale",
			Labels: map[string]string{
				kubetypes.LabelManaged: "true",
				LabelParentName:        "external-service",
				LabelParentNamespace:   "default",
				LabelParentType:        "svc",
				labelProxyGroup:        "test-proxy-group",
				labelSvcType:           typeEgress,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.0.100.50", // This IP should be used in DNS, not Pod IPs
			Ports: []corev1.ServicePort{{
				Port:       443,
				TargetPort: intstr.FromInt(10443), // Port mapping
			}},
		},
	}

	// Create EndpointSlice with Pod IPs (these should NOT be used in DNS records)
	proxyGroupEps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ts-proxygroup-egress-abcd1-ipv4",
			Namespace: "tailscale",
			Labels: map[string]string{
				discoveryv1.LabelServiceName: "ts-proxygroup-egress-abcd1",
				kubetypes.LabelManaged:       "true",
				LabelParentName:              "external-service",
				LabelParentNamespace:         "default",
				LabelParentType:              "svc",
				labelProxyGroup:              "test-proxy-group",
				labelSvcType:                 typeEgress,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"10.1.0.100", "10.1.0.101", "10.1.0.102"}, // Pod IPs that should NOT be used
			Conditions: discoveryv1.EndpointConditions{
				Ready:       ptr.To(true),
				Serving:     ptr.To(true),
				Terminating: ptr.To(false),
			},
		}},
		Ports: []discoveryv1.EndpointPort{{
			Port: ptr.To(int32(10443)),
		}},
	}

	mustCreate(t, fc, proxyGroupEgressSvc)
	mustCreate(t, fc, proxyGroupEps)
	expectReconciled(t, dnsRR, "tailscale", "ts-proxygroup-egress-abcd1")

	// Verify DNS record uses ClusterIP Service IP, not Pod IPs
	wantHosts["external-service.example.ts.net"] = []string{"10.0.100.50"}
	expectHostsRecords(t, fc, wantHosts)

	// 9. ProxyGroup egress DNS record updates when ClusterIP changes
	t.Log("test case 9: ProxyGroup egress ClusterIP change")
	mustUpdate(t, fc, "tailscale", "ts-proxygroup-egress-abcd1", func(svc *corev1.Service) {
		svc.Spec.ClusterIP = "10.0.100.51"
	})
	expectReconciled(t, dnsRR, "tailscale", "ts-proxygroup-egress-abcd1")
	wantHosts["external-service.example.ts.net"] = []string{"10.0.100.51"}
	expectHostsRecords(t, fc, wantHosts)

	// 10. Test ProxyGroup service deletion and DNS cleanup
	t.Log("test case 10: ProxyGroup egress service deletion")
	mustDeleteAll(t, fc, proxyGroupEgressSvc)
	expectReconciled(t, dnsRR, "tailscale", "ts-proxygroup-egress-abcd1")
	delete(wantHosts, "external-service.example.ts.net")
	expectHostsRecords(t, fc, wantHosts)
}

func TestDNSRecordsReconcilerErrorCases(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	dnsRR := &dnsRecordsReconciler{
		logger: zl.Sugar(),
	}

	testSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
	}

	// Test invalid IP format
	testSvc.Spec.ClusterIP = "invalid-ip"
	_, _, err = dnsRR.getClusterIPServiceIPs(testSvc, zl.Sugar())
	if err == nil {
		t.Error("expected error for invalid IP format")
	}

	// Test valid IP
	testSvc.Spec.ClusterIP = "10.0.100.50"
	ip4s, ip6s, err := dnsRR.getClusterIPServiceIPs(testSvc, zl.Sugar())
	if err != nil {
		t.Errorf("unexpected error for valid IP: %v", err)
	}
	if len(ip4s) != 1 || ip4s[0] != "10.0.100.50" {
		t.Errorf("expected IPv4 address 10.0.100.50, got %v", ip4s)
	}
	if len(ip6s) != 0 {
		t.Errorf("expected no IPv6 addresses, got %v", ip6s)
	}
}

func TestDNSRecordsReconcilerDualStack(t *testing.T) {
	// Test dual-stack (IPv4 and IPv6) scenarios
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	// Preconfigure cluster with DNSConfig
	dnsCfg := &tsapi.DNSConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		TypeMeta:   metav1.TypeMeta{Kind: "DNSConfig"},
		Spec:       tsapi.DNSConfigSpec{Nameserver: &tsapi.Nameserver{}},
	}
	dnsCfg.Status.Conditions = append(dnsCfg.Status.Conditions, metav1.Condition{
		Type:   string(tsapi.NameserverReady),
		Status: metav1.ConditionTrue,
	})

	// Create dual-stack ingress
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dual-stack-ingress",
			Namespace: "test",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: []networkingv1.IngressLoadBalancerIngress{
					{Hostname: "dual-stack.example.ts.net"},
				},
			},
		},
	}

	headlessSvc := headlessSvcForParent(ing, "ingress")
	headlessSvc.Name = "ts-dual-stack-ingress"
	headlessSvc.SetLabels(map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentName:        "dual-stack-ingress",
		LabelParentNamespace:   "test",
		LabelParentType:        "ingress",
	})

	// Create both IPv4 and IPv6 endpoints
	epv4 := endpointSliceForService(headlessSvc, "10.1.2.3", discoveryv1.AddressTypeIPv4)
	epv6 := endpointSliceForService(headlessSvc, "2001:db8::1", discoveryv1.AddressTypeIPv6)

	dnsRRDualStack := &dnsRecordsReconciler{
		tsNamespace: "tailscale",
		logger:      zl.Sugar(),
	}

	// Create the dnsrecords ConfigMap
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      operatorutils.DNSRecordsCMName,
			Namespace: "tailscale",
		},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(dnsCfg, ing, headlessSvc, epv4, epv6, cm).
		WithStatusSubresource(dnsCfg).
		Build()

	dnsRRDualStack.Client = fc

	// Test dual-stack service records
	expectReconciled(t, dnsRRDualStack, "tailscale", "ts-dual-stack-ingress")

	wantIPv4 := map[string][]string{"dual-stack.example.ts.net": {"10.1.2.3"}}
	wantIPv6 := map[string][]string{"dual-stack.example.ts.net": {"2001:db8::1"}}
	expectHostsRecordsWithIPv6(t, fc, wantIPv4, wantIPv6)

	// Test ProxyGroup with dual-stack ClusterIPs
	// First create parent service
	parentEgressSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pg-service",
			Namespace: "tailscale",
			Annotations: map[string]string{
				AnnotationTailnetTargetFQDN: "pg-service.example.ts.net",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "unused",
		},
	}

	proxyGroupSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ts-proxygroup-dualstack",
			Namespace: "tailscale",
			Labels: map[string]string{
				kubetypes.LabelManaged: "true",
				labelProxyGroup:        "test-pg",
				labelSvcType:           typeEgress,
				LabelParentName:        "pg-service",
				LabelParentNamespace:   "tailscale",
				LabelParentType:        "svc",
			},
			Annotations: map[string]string{
				annotationTSMagicDNSName: "pg-service.example.ts.net",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:       corev1.ServiceTypeClusterIP,
			ClusterIP:  "10.96.0.100",
			ClusterIPs: []string{"10.96.0.100", "2001:db8::100"},
		},
	}

	mustCreate(t, fc, parentEgressSvc)
	mustCreate(t, fc, proxyGroupSvc)
	expectReconciled(t, dnsRRDualStack, "tailscale", "ts-proxygroup-dualstack")

	wantIPv4["pg-service.example.ts.net"] = []string{"10.96.0.100"}
	wantIPv6["pg-service.example.ts.net"] = []string{"2001:db8::100"}
	expectHostsRecordsWithIPv6(t, fc, wantIPv4, wantIPv6)
}

func headlessSvcForParent(o client.Object, typ string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      o.GetName(),
			Namespace: "tailscale",
			Labels: map[string]string{
				kubetypes.LabelManaged: "true",
				LabelParentName:        o.GetName(),
				LabelParentNamespace:   o.GetNamespace(),
				LabelParentType:        typ,
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Type:      corev1.ServiceTypeClusterIP,
			Selector:  map[string]string{"foo": "bar"},
		},
	}
}

func endpointSliceForService(svc *corev1.Service, ip string, fam discoveryv1.AddressType) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", svc.Name, string(fam)),
			Namespace: svc.Namespace,
			Labels:    map[string]string{discoveryv1.LabelServiceName: svc.Name},
		},
		AddressType: fam,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{ip},
			Conditions: discoveryv1.EndpointConditions{
				Ready:       ptr.To(true),
				Serving:     ptr.To(true),
				Terminating: ptr.To(false),
			},
		}},
	}
}

func expectHostsRecords(t *testing.T, cl client.Client, wantsHosts map[string][]string) {
	t.Helper()
	cm := new(corev1.ConfigMap)
	if err := cl.Get(context.Background(), types.NamespacedName{Name: "dnsrecords", Namespace: "tailscale"}, cm); err != nil {
		t.Fatalf("getting dnsconfig ConfigMap: %v", err)
	}
	if cm.Data == nil {
		t.Fatal("dnsconfig ConfigMap has no data")
	}
	dnsConfigString, ok := cm.Data[operatorutils.DNSRecordsCMKey]
	if !ok {
		t.Fatal("dnsconfig ConfigMap does not contain dnsconfig")
	}
	dnsConfig := &operatorutils.Records{}
	if err := json.Unmarshal([]byte(dnsConfigString), dnsConfig); err != nil {
		t.Fatalf("unmarshaling dnsconfig: %v", err)
	}
	if diff := cmp.Diff(dnsConfig.IP4, wantsHosts); diff != "" {
		t.Fatalf("unexpected dns config (-got +want):\n%s", diff)
	}
}

func expectHostsRecordsWithIPv6(t *testing.T, cl client.Client, wantsHostsIPv4, wantsHostsIPv6 map[string][]string) {
	t.Helper()
	cm := new(corev1.ConfigMap)
	if err := cl.Get(context.Background(), types.NamespacedName{Name: "dnsrecords", Namespace: "tailscale"}, cm); err != nil {
		t.Fatalf("getting dnsconfig ConfigMap: %v", err)
	}
	if cm.Data == nil {
		t.Fatal("dnsconfig ConfigMap has no data")
	}
	dnsConfigString, ok := cm.Data[operatorutils.DNSRecordsCMKey]
	if !ok {
		t.Fatal("dnsconfig ConfigMap does not contain dnsconfig")
	}
	dnsConfig := &operatorutils.Records{}
	if err := json.Unmarshal([]byte(dnsConfigString), dnsConfig); err != nil {
		t.Fatalf("unmarshaling dnsconfig: %v", err)
	}
	if diff := cmp.Diff(dnsConfig.IP4, wantsHostsIPv4); diff != "" {
		t.Fatalf("unexpected IPv4 dns config (-got +want):\n%s", diff)
	}
	if diff := cmp.Diff(dnsConfig.IP6, wantsHostsIPv6); diff != "" {
		t.Fatalf("unexpected IPv6 dns config (-got +want):\n%s", diff)
	}
}
