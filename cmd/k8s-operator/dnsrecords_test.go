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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
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
	mustUpdateStatus[tsapi.DNSConfig](t, fc, "", "test", func(c *tsapi.DNSConfig) {
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
	wantHosts := map[string][]string{"foo.bar.ts.net": {"10.9.8.7"}} // IPv6 endpoint is currently ignored
	expectHostsRecords(t, fc, wantHosts)

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
}

func headlessSvcForParent(o client.Object, typ string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      o.GetName(),
			Namespace: "tailscale",
			Labels: map[string]string{
				LabelManaged:         "true",
				LabelParentName:      o.GetName(),
				LabelParentNamespace: o.GetNamespace(),
				LabelParentType:      typ,
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
