// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
)

func TestTailscaleIngress(t *testing.T) {
	tsIngressClass := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "tailscale"}, Spec: networkingv1.IngressClassSpec{Controller: "tailscale.com/ts-ingress"}}
	fc := fake.NewFakeClient(tsIngressClass)
	ft := &fakeTSClient{}
	fakeTsnetServer := &fakeTSNetServer{certDomains: []string{"foo.com"}}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	ingR := &IngressReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			tsnetServer:       fakeTsnetServer,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
	}

	// 1. Resources get created for regular Ingress
	ing := &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "test",
					Port: networkingv1.ServiceBackendPort{
						Number: 8080,
					},
				},
			},
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"default-test"}},
			},
		},
	}
	mustCreate(t, fc, ing)
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "1.2.3.4",
			Ports: []corev1.ServicePort{{
				Port: 8080,
				Name: "http"},
			},
		},
	})

	expectReconciled(t, ingR, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "ingress")
	opts := configOpts{
		stsName:    shortName,
		secretName: fullName,
		namespace:  "default",
		parentType: "ingress",
		hostname:   "default-test",
		app:        kubetypes.AppIngressResource,
	}
	serveConfig := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{"${TS_CERT_DOMAIN}:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: "http://1.2.3.4:8080/"}}}},
	}
	opts.serveConfig = serveConfig

	expectEqual(t, fc, expectedSecret(t, fc, opts), nil)
	expectEqual(t, fc, expectedHeadlessService(shortName, "ingress"), nil)
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation)

	// 2. Ingress status gets updated with ingress proxy's MagicDNS name
	// once that becomes available.
	mustUpdate(t, fc, "operator-ns", opts.secretName, func(secret *corev1.Secret) {
		mak.Set(&secret.Data, "device_id", []byte("1234"))
		mak.Set(&secret.Data, "device_fqdn", []byte("foo.tailnetxyz.ts.net"))
	})
	expectReconciled(t, ingR, "default", "test")
	ing.Finalizers = append(ing.Finalizers, "tailscale.com/finalizer")
	ing.Status.LoadBalancer = networkingv1.IngressLoadBalancerStatus{
		Ingress: []networkingv1.IngressLoadBalancerIngress{
			{Hostname: "foo.tailnetxyz.ts.net", Ports: []networkingv1.IngressPortStatus{{Port: 443, Protocol: "TCP"}}},
		},
	}
	expectEqual(t, fc, ing, nil)

	// 3. Resources get created for Ingress that should allow forwarding
	// cluster traffic
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		mak.Set(&ing.ObjectMeta.Annotations, AnnotationExperimentalForwardClusterTrafficViaL7IngresProxy, "true")
	})
	opts.shouldEnableForwardingClusterTrafficViaIngress = true
	expectReconciled(t, ingR, "default", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

	// 4. Resources get cleaned up when Ingress class is unset
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		ing.Spec.IngressClassName = ptr.To("nginx")
	})
	expectReconciled(t, ingR, "default", "test")
	expectReconciled(t, ingR, "default", "test") // deleting Ingress STS requires two reconciles
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Service](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)
}

func TestTailscaleIngressHostname(t *testing.T) {
	tsIngressClass := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "tailscale"}, Spec: networkingv1.IngressClassSpec{Controller: "tailscale.com/ts-ingress"}}
	fc := fake.NewFakeClient(tsIngressClass)
	ft := &fakeTSClient{}
	fakeTsnetServer := &fakeTSNetServer{certDomains: []string{"foo.com"}}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	ingR := &IngressReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			tsnetServer:       fakeTsnetServer,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
	}

	// 1. Resources get created for regular Ingress
	ing := &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "test",
					Port: networkingv1.ServiceBackendPort{
						Number: 8080,
					},
				},
			},
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"default-test"}},
			},
		},
	}
	mustCreate(t, fc, ing)
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "1.2.3.4",
			Ports: []corev1.ServicePort{{
				Port: 8080,
				Name: "http"},
			},
		},
	})

	expectReconciled(t, ingR, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "ingress")
	mustCreate(t, fc, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fullName,
			Namespace: "operator-ns",
			UID:       "test-uid",
		},
	})
	opts := configOpts{
		stsName:    shortName,
		secretName: fullName,
		namespace:  "default",
		parentType: "ingress",
		hostname:   "default-test",
		app:        kubetypes.AppIngressResource,
	}
	serveConfig := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{"${TS_CERT_DOMAIN}:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: "http://1.2.3.4:8080/"}}}},
	}
	opts.serveConfig = serveConfig

	expectEqual(t, fc, expectedSecret(t, fc, opts), nil)
	expectEqual(t, fc, expectedHeadlessService(shortName, "ingress"), nil)
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation)

	// 2. Ingress proxy with capability version >= 110 does not have an HTTPS endpoint set
	mustUpdate(t, fc, "operator-ns", opts.secretName, func(secret *corev1.Secret) {
		mak.Set(&secret.Data, "device_id", []byte("1234"))
		mak.Set(&secret.Data, "tailscale_capver", []byte("110"))
		mak.Set(&secret.Data, "pod_uid", []byte("test-uid"))
		mak.Set(&secret.Data, "device_fqdn", []byte("foo.tailnetxyz.ts.net"))
	})
	expectReconciled(t, ingR, "default", "test")
	ing.Finalizers = append(ing.Finalizers, "tailscale.com/finalizer")

	expectEqual(t, fc, ing, nil)

	// 3. Ingress proxy with capability version >= 110 advertises HTTPS endpoint
	mustUpdate(t, fc, "operator-ns", opts.secretName, func(secret *corev1.Secret) {
		mak.Set(&secret.Data, "device_id", []byte("1234"))
		mak.Set(&secret.Data, "tailscale_capver", []byte("110"))
		mak.Set(&secret.Data, "pod_uid", []byte("test-uid"))
		mak.Set(&secret.Data, "device_fqdn", []byte("foo.tailnetxyz.ts.net"))
		mak.Set(&secret.Data, "https_endpoint", []byte("foo.tailnetxyz.ts.net"))
	})
	expectReconciled(t, ingR, "default", "test")
	ing.Status.LoadBalancer = networkingv1.IngressLoadBalancerStatus{
		Ingress: []networkingv1.IngressLoadBalancerIngress{
			{Hostname: "foo.tailnetxyz.ts.net", Ports: []networkingv1.IngressPortStatus{{Port: 443, Protocol: "TCP"}}},
		},
	}
	expectEqual(t, fc, ing, nil)

	// 4. Ingress proxy with capability version >= 110 does not have an HTTPS endpoint ready
	mustUpdate(t, fc, "operator-ns", opts.secretName, func(secret *corev1.Secret) {
		mak.Set(&secret.Data, "device_id", []byte("1234"))
		mak.Set(&secret.Data, "tailscale_capver", []byte("110"))
		mak.Set(&secret.Data, "pod_uid", []byte("test-uid"))
		mak.Set(&secret.Data, "device_fqdn", []byte("foo.tailnetxyz.ts.net"))
		mak.Set(&secret.Data, "https_endpoint", []byte("no-https"))
	})
	expectReconciled(t, ingR, "default", "test")
	ing.Status.LoadBalancer.Ingress = nil
	expectEqual(t, fc, ing, nil)

	// 5. Ingress proxy's state has https_endpoints set, but its capver is not matching Pod UID (downgrade)
	mustUpdate(t, fc, "operator-ns", opts.secretName, func(secret *corev1.Secret) {
		mak.Set(&secret.Data, "device_id", []byte("1234"))
		mak.Set(&secret.Data, "tailscale_capver", []byte("110"))
		mak.Set(&secret.Data, "pod_uid", []byte("not-the-right-uid"))
		mak.Set(&secret.Data, "device_fqdn", []byte("foo.tailnetxyz.ts.net"))
		mak.Set(&secret.Data, "https_endpoint", []byte("bar.tailnetxyz.ts.net"))
	})
	ing.Status.LoadBalancer = networkingv1.IngressLoadBalancerStatus{
		Ingress: []networkingv1.IngressLoadBalancerIngress{
			{Hostname: "foo.tailnetxyz.ts.net", Ports: []networkingv1.IngressPortStatus{{Port: 443, Protocol: "TCP"}}},
		},
	}
	expectReconciled(t, ingR, "default", "test")
	expectEqual(t, fc, ing, nil)
}

func TestTailscaleIngressWithProxyClass(t *testing.T) {
	// Setup
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-metadata"},
		Spec: tsapi.ProxyClassSpec{StatefulSet: &tsapi.StatefulSet{
			Labels:      map[string]string{"foo": "bar"},
			Annotations: map[string]string{"bar.io/foo": "some-val"},
			Pod:         &tsapi.Pod{Annotations: map[string]string{"foo.io/bar": "some-val"}}}},
	}
	tsIngressClass := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "tailscale"}, Spec: networkingv1.IngressClassSpec{Controller: "tailscale.com/ts-ingress"}}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc, tsIngressClass).
		WithStatusSubresource(pc).
		Build()
	ft := &fakeTSClient{}
	fakeTsnetServer := &fakeTSNetServer{certDomains: []string{"foo.com"}}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	ingR := &IngressReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			tsnetServer:       fakeTsnetServer,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
	}

	// 1. Ingress is created with no ProxyClass specified, default proxy
	// resources get configured.
	ing := &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "test",
					Port: networkingv1.ServiceBackendPort{
						Number: 8080,
					},
				},
			},
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"default-test"}},
			},
		},
	}
	mustCreate(t, fc, ing)
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "1.2.3.4",
			Ports: []corev1.ServicePort{{
				Port: 8080,
				Name: "http"},
			},
		},
	})

	expectReconciled(t, ingR, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "ingress")
	opts := configOpts{
		stsName:    shortName,
		secretName: fullName,
		namespace:  "default",
		parentType: "ingress",
		hostname:   "default-test",
		app:        kubetypes.AppIngressResource,
	}
	serveConfig := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{"${TS_CERT_DOMAIN}:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: "http://1.2.3.4:8080/"}}}},
	}
	opts.serveConfig = serveConfig

	expectEqual(t, fc, expectedSecret(t, fc, opts), nil)
	expectEqual(t, fc, expectedHeadlessService(shortName, "ingress"), nil)
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation)

	// 2. Ingress is updated to specify a ProxyClass, ProxyClass is not yet
	// ready, so proxy resource configuration does not change.
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		mak.Set(&ing.ObjectMeta.Labels, LabelProxyClass, "custom-metadata")
	})
	expectReconciled(t, ingR, "default", "test")
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation)

	// 3. ProxyClass is set to Ready by proxy-class reconciler. Ingress get
	// reconciled and configuration from the ProxyClass is applied to the
	// created proxy resources.
	mustUpdateStatus(t, fc, "", "custom-metadata", func(pc *tsapi.ProxyClass) {
		pc.Status = tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassReady),
				ObservedGeneration: pc.Generation,
			}}}
	})
	expectReconciled(t, ingR, "default", "test")
	opts.proxyClass = pc.Name
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation)

	// 4. tailscale.com/proxy-class label is removed from the Ingress, the
	// Ingress gets reconciled and the custom ProxyClass configuration is
	// removed from the proxy resources.
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		delete(ing.ObjectMeta.Labels, LabelProxyClass)
	})
	expectReconciled(t, ingR, "default", "test")
	opts.proxyClass = ""
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation)
}

func TestTailscaleIngressWithServiceMonitor(t *testing.T) {
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "metrics", Generation: 1},
		Spec: tsapi.ProxyClassSpec{
			Metrics: &tsapi.Metrics{
				Enable:         true,
				ServiceMonitor: &tsapi.ServiceMonitor{Enable: true},
			},
		},
		Status: tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassReady),
				ObservedGeneration: 1,
			}}},
	}
	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: serviceMonitorCRD}}
	tsIngressClass := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "tailscale"}, Spec: networkingv1.IngressClassSpec{Controller: "tailscale.com/ts-ingress"}}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc, tsIngressClass).
		WithStatusSubresource(pc).
		Build()
	ft := &fakeTSClient{}
	fakeTsnetServer := &fakeTSNetServer{certDomains: []string{"foo.com"}}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	ingR := &IngressReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			tsnetServer:       fakeTsnetServer,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
	}
	// 1. Enable metrics- expect metrics Service to be created
	ing := &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Labels: map[string]string{
				"tailscale.com/proxy-class": "metrics",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "test",
					Port: networkingv1.ServiceBackendPort{
						Number: 8080,
					},
				},
			},
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"default-test"}},
			},
		},
	}
	mustCreate(t, fc, ing)
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "1.2.3.4",
			Ports: []corev1.ServicePort{{
				Port: 8080,
				Name: "http"},
			},
		},
	})

	expectReconciled(t, ingR, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "ingress")
	opts := configOpts{
		stsName:            shortName,
		secretName:         fullName,
		namespace:          "default",
		tailscaleNamespace: "operator-ns",
		parentType:         "ingress",
		hostname:           "default-test",
		app:                kubetypes.AppIngressResource,
		enableMetrics:      true,
		namespaced:         true,
		proxyType:          proxyTypeIngressResource,
	}
	serveConfig := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{"${TS_CERT_DOMAIN}:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: "http://1.2.3.4:8080/"}}}},
	}
	opts.serveConfig = serveConfig

	expectEqual(t, fc, expectedSecret(t, fc, opts), nil)
	expectEqual(t, fc, expectedHeadlessService(shortName, "ingress"), nil)
	expectEqual(t, fc, expectedMetricsService(opts), nil)
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation)
	// 2. Enable ServiceMonitor - should not error when there is no ServiceMonitor CRD in cluster
	mustUpdate(t, fc, "", "metrics", func(pc *tsapi.ProxyClass) {
		pc.Spec.Metrics.ServiceMonitor = &tsapi.ServiceMonitor{Enable: true}
	})
	expectReconciled(t, ingR, "default", "test")
	// 3. Create ServiceMonitor CRD and reconcile- ServiceMonitor should get created
	mustCreate(t, fc, crd)
	expectReconciled(t, ingR, "default", "test")
	expectEqualUnstructured(t, fc, expectedServiceMonitor(t, opts))
}
