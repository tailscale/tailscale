// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
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
	"tailscale.com/client/tailscale/apitype"
	k8soperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
)

func TestDNSRecordsReconciler(t *testing.T) {
	// Preconfigure a cluster with DNSConfig
	dnsConfig := &tsapi.DNSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		TypeMeta: metav1.TypeMeta{Kind: "DNSConfig"},
		Spec: tsapi.DNSConfigSpec{
			Nameserver: &tsapi.Nameserver{},
		}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "dnsconfig", Namespace: "tailscale"}}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(cm).
		WithObjects(dnsConfig).
		WithStatusSubresource(dnsConfig).
		Build()
	ft := &fakeTSLocalClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	// Set the ready condition of the DNSConfig
	mustUpdateStatus[tsapi.DNSConfig](t, fc, "", "test", func(c *tsapi.DNSConfig) {
		k8soperator.SetDNSConfigCondition(c, tsapi.NameserverReady, metav1.ConditionTrue, reasonNameserverCreated, reasonNameserverCreated, 0, cl, zl.Sugar())
	})
	dnsRR := &dnsRecordsReconciler{
		Client:         fc,
		logger:         zl.Sugar(),
		localAPIClient: ft,
		tsNamespace:    "tailscale",
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
	ep := endpointSliceForService(headlessForEgressSvcFQDN, "10.9.8.7")
	mustCreate(t, fc, egressSvcFQDN)
	mustCreate(t, fc, headlessForEgressSvcFQDN)
	mustCreate(t, fc, ep)
	expectReconciled(t, dnsRR, "tailscale", "egress-fqdn") // dns-records-reconciler reconcile the headless Service
	// ConfigMap should now have a record for foo.bar.ts.net -> 10.8.8.7
	wantHosts := map[string][]string{"foo.bar.ts.net": {"10.9.8.7"}}
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
	ep = endpointSliceForService(headlessForEgressSvcFQDN, "10.6.5.4")
	mustUpdate(t, fc, ep.Namespace, ep.Name, func(ep *discoveryv1.EndpointSlice) {
		ep.Endpoints[0].Addresses = []string{"10.6.5.4"}
	})
	expectReconciled(t, dnsRR, "tailscale", "egress-fqdn") // dns-records-reconciler reconcile the headless Service
	wantHosts = map[string][]string{"baz.bar.ts.net": {"10.6.5.4"}}
	expectHostsRecords(t, fc, wantHosts)

	// 4. DNS record is created for an egress proxy configured via
	// tailscale.com/tailnet-ip annotation
	egressSvcIP := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "egress-ip",
			Namespace:   "test",
			Annotations: map[string]string{"tailscale.com/tailnet-ip": "foo.baz.ts.net"},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "unused",
			Type:         corev1.ServiceTypeExternalName,
		},
	}
	headlessForEgressSvcIP := headlessSvcForParent(egressSvcIP, "svc")
	ep = endpointSliceForService(headlessForEgressSvcIP, "10.9.8.7")
	mustCreate(t, fc, egressSvcIP)
	mustCreate(t, fc, headlessForEgressSvcIP)
	mustCreate(t, fc, ep)
	ft.whoisResponse = &apitype.WhoIsResponse{Node: &tailcfg.Node{Name: "some.node.ts.net"}}
	expectReconciled(t, dnsRR, "tailscale", "egress-ip") // dns-records-reconciler should have reconcile the headless Service
	wantHosts["some.node.ts.net"] = []string{"10.9.8.7"}
	expectHostsRecords(t, fc, wantHosts)

	// 5. DNS record is created for an ingress proxy configured via Ingress
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
	headlessForIngress := headlessSvcForParent(ing, "ingress")
	ep = endpointSliceForService(headlessForIngress, "10.9.8.7")
	mustCreate(t, fc, ing)
	mustCreate(t, fc, headlessForIngress)
	mustCreate(t, fc, ep)
	expectReconciled(t, dnsRR, "tailscale", "ts-ingress") // dns-records-reconciler should reconcile the headless Service
	wantHosts["cluster.ingress.ts.net"] = []string{"10.9.8.7"}
	expectHostsRecords(t, fc, wantHosts)

	// 6. DNS record is created for an ingress proxy configured via a LoadBalancer Service
	ingressSvcLB := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-lb",
			Namespace: "test",
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{Hostname: "ingress.lb.ts.net"}},
			},
		},
	}
	headlessForIngresLB := headlessSvcForParent(ingressSvcLB, "svc")
	ep = endpointSliceForService(headlessForIngresLB, "10.9.8.7")
	mustCreate(t, fc, ingressSvcLB)
	mustCreate(t, fc, headlessForIngresLB)
	mustCreate(t, fc, ep)
	expectReconciled(t, dnsRR, "tailscale", "ingress-lb") // dns-records-reconciler should reconcile the headless Service
	wantHosts["ingress.lb.ts.net"] = []string{"10.9.8.7"}
	expectHostsRecords(t, fc, wantHosts)

	// 7. DNS record is created for an ingress proxy configured via an annotation
	ingressSvcAnnot := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "ingress-annot",
			Namespace:   "test",
			Annotations: map[string]string{AnnotationExpose: "true"},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
	}
	stateSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-annot",
			Namespace: "tailscale",
			Labels: map[string]string{
				LabelManaged:         "true",
				LabelParentName:      "ingress-annot",
				LabelParentNamespace: "test",
				LabelParentType:      "svc",
			},
		},
		Data: map[string][]byte{"device_fqdn": []byte("cluster.node.ts.net")},
	}
	headlessForIngresAnnot := headlessSvcForParent(ingressSvcAnnot, "svc")
	ep = endpointSliceForService(headlessForIngresAnnot, "10.9.8.7")
	mustCreate(t, fc, ingressSvcAnnot)
	mustCreate(t, fc, headlessForIngresAnnot)
	mustCreate(t, fc, ep)
	mustCreate(t, fc, stateSecret)
	expectReconciled(t, dnsRR, "tailscale", "ingress-annot") // dns-records-reconciler should reconcile the headless Service
	wantHosts["cluster.node.ts.net"] = []string{"10.9.8.7"}
	expectHostsRecords(t, fc, wantHosts)

	// TODO  (irbekrm): devise a way how to test deletion
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

func endpointSliceForService(svc *corev1.Service, ip string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svc.Name,
			Namespace: svc.Namespace,
			Labels:    map[string]string{discoveryv1.LabelServiceName: svc.Name},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{ip},
		}},
	}
}

func expectHostsRecords(t *testing.T, cl client.Client, wantsHosts map[string][]string) {
	t.Helper()
	cm := new(corev1.ConfigMap)
	if err := cl.Get(context.Background(), types.NamespacedName{Name: "dnsconfig", Namespace: "tailscale"}, cm); err != nil {
		t.Fatalf("getting dnsconfig ConfigMap: %v", err)
	}
	if cm.Data == nil {
		t.Fatal("dnsconfig ConfigMap has no data")
	}
	dnsConfigString, ok := cm.Data[dnsConfigKey]
	if !ok {
		t.Fatal("dnsconfig ConfigMap does not contain dnsconfig")
	}
	dnsConfig := &k8soperator.TSHosts{}
	if err := json.Unmarshal([]byte(dnsConfigString), dnsConfig); err != nil {
		t.Fatalf("unmarshaling dnsconfig: %v", err)
	}
	if diff := cmp.Diff(dnsConfig.Hosts, wantsHosts); diff != "" {
		t.Fatalf("unexpected dns config (-got +want):\n%s", diff)
	}
}
