// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
)

func TestTailscaleIngress(t *testing.T) {
	fc := fake.NewFakeClient(ingressClass())
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
	mustCreate(t, fc, ingress())
	mustCreate(t, fc, service())

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

	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "ingress"))
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation, removeResourceReqs)

	// 2. Ingress status gets updated with ingress proxy's MagicDNS name
	// once that becomes available.
	mustUpdate(t, fc, "operator-ns", opts.secretName, func(secret *corev1.Secret) {
		mak.Set(&secret.Data, "device_id", []byte("1234"))
		mak.Set(&secret.Data, "device_fqdn", []byte("foo.tailnetxyz.ts.net"))
	})
	expectReconciled(t, ingR, "default", "test")

	// Get the ingress and update it with expected changes
	ing := ingress()
	ing.Finalizers = append(ing.Finalizers, "tailscale.com/finalizer")
	ing.Status.LoadBalancer = networkingv1.IngressLoadBalancerStatus{
		Ingress: []networkingv1.IngressLoadBalancerIngress{
			{Hostname: "foo.tailnetxyz.ts.net", Ports: []networkingv1.IngressPortStatus{{Port: 443, Protocol: "TCP"}}},
		},
	}
	expectEqual(t, fc, ing)

	// 3. Resources get created for Ingress that should allow forwarding
	// cluster traffic
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		mak.Set(&ing.ObjectMeta.Annotations, AnnotationExperimentalForwardClusterTrafficViaL7IngresProxy, "true")
	})
	opts.shouldEnableForwardingClusterTrafficViaIngress = true
	expectReconciled(t, ingR, "default", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation, removeResourceReqs)

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
	fc := fake.NewFakeClient(ingressClass())
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
	mustCreate(t, fc, ingress())
	mustCreate(t, fc, service())

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

	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "ingress"))
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation, removeResourceReqs)

	// 2. Ingress proxy with capability version >= 110 does not have an HTTPS endpoint set
	mustUpdate(t, fc, "operator-ns", opts.secretName, func(secret *corev1.Secret) {
		mak.Set(&secret.Data, "device_id", []byte("1234"))
		mak.Set(&secret.Data, "tailscale_capver", []byte("110"))
		mak.Set(&secret.Data, "pod_uid", []byte("test-uid"))
		mak.Set(&secret.Data, "device_fqdn", []byte("foo.tailnetxyz.ts.net"))
	})
	expectReconciled(t, ingR, "default", "test")

	// Get the ingress and update it with expected changes
	ing := ingress()
	ing.Finalizers = append(ing.Finalizers, "tailscale.com/finalizer")
	expectEqual(t, fc, ing)

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
	expectEqual(t, fc, ing)

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
	expectEqual(t, fc, ing)

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
	expectEqual(t, fc, ing)
}

func TestTailscaleIngressWithProxyClass(t *testing.T) {
	// Setup
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-metadata"},
		Spec: tsapi.ProxyClassSpec{StatefulSet: &tsapi.StatefulSet{
			Labels:      tsapi.Labels{"foo": "bar"},
			Annotations: map[string]string{"bar.io/foo": "some-val"},
			Pod:         &tsapi.Pod{Annotations: map[string]string{"foo.io/bar": "some-val"}}}},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc, ingressClass()).
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
	mustCreate(t, fc, ingress())
	mustCreate(t, fc, service())

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

	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "ingress"))
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation, removeResourceReqs)

	// 2. Ingress is updated to specify a ProxyClass, ProxyClass is not yet
	// ready, so proxy resource configuration does not change.
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		mak.Set(&ing.ObjectMeta.Labels, LabelProxyClass, "custom-metadata")
	})
	expectReconciled(t, ingR, "default", "test")
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation, removeResourceReqs)

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
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation, removeResourceReqs)

	// 4. tailscale.com/proxy-class label is removed from the Ingress, the
	// Ingress gets reconciled and the custom ProxyClass configuration is
	// removed from the proxy resources.
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		delete(ing.ObjectMeta.Labels, LabelProxyClass)
	})
	expectReconciled(t, ingR, "default", "test")
	opts.proxyClass = ""
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeHashAnnotation, removeResourceReqs)
}

func TestTailscaleIngressWithServiceMonitor(t *testing.T) {
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "metrics", Generation: 1},
		Spec:       tsapi.ProxyClassSpec{},
		Status: tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassReady),
				ObservedGeneration: 1,
			}}},
	}
	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: serviceMonitorCRD}}

	// Create fake client with ProxyClass, IngressClass, Ingress with metrics ProxyClass, and Service
	ing := ingress()
	ing.Labels = map[string]string{
		LabelProxyClass: "metrics",
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc, ingressClass(), ing, service()).
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
	expectReconciled(t, ingR, "default", "test")
	fullName, shortName := findGenName(t, fc, "default", "test", "ingress")
	serveConfig := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{"${TS_CERT_DOMAIN}:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: "http://1.2.3.4:8080/"}}}},
	}
	opts := configOpts{
		stsName:            shortName,
		secretName:         fullName,
		namespace:          "default",
		tailscaleNamespace: "operator-ns",
		parentType:         "ingress",
		hostname:           "default-test",
		app:                kubetypes.AppIngressResource,
		namespaced:         true,
		proxyType:          proxyTypeIngressResource,
		serveConfig:        serveConfig,
		resourceVersion:    "1",
	}

	// 1. Enable metrics- expect metrics Service to be created
	mustUpdate(t, fc, "", "metrics", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.Metrics = &tsapi.Metrics{Enable: true}
	})
	opts.enableMetrics = true

	expectReconciled(t, ingR, "default", "test")

	expectEqual(t, fc, expectedMetricsService(opts))

	// 2. Enable ServiceMonitor - should not error when there is no ServiceMonitor CRD in cluster
	mustUpdate(t, fc, "", "metrics", func(pc *tsapi.ProxyClass) {
		pc.Spec.Metrics.ServiceMonitor = &tsapi.ServiceMonitor{Enable: true, Labels: tsapi.Labels{"foo": "bar"}}
	})
	expectReconciled(t, ingR, "default", "test")
	expectEqual(t, fc, expectedMetricsService(opts))

	// 3. Create ServiceMonitor CRD and reconcile- ServiceMonitor should get created
	mustCreate(t, fc, crd)
	expectReconciled(t, ingR, "default", "test")
	opts.serviceMonitorLabels = tsapi.Labels{"foo": "bar"}
	expectEqual(t, fc, expectedMetricsService(opts))
	expectEqualUnstructured(t, fc, expectedServiceMonitor(t, opts))

	// 4. Update ServiceMonitor CRD and reconcile- ServiceMonitor should get updated
	mustUpdate(t, fc, pc.Namespace, pc.Name, func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.Metrics.ServiceMonitor.Labels = nil
	})
	expectReconciled(t, ingR, "default", "test")
	opts.serviceMonitorLabels = nil
	opts.resourceVersion = "2"
	expectEqual(t, fc, expectedMetricsService(opts))
	expectEqualUnstructured(t, fc, expectedServiceMonitor(t, opts))

	// 5. Disable metrics - metrics resources should get deleted.
	mustUpdate(t, fc, pc.Namespace, pc.Name, func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.Metrics = nil
	})
	expectReconciled(t, ingR, "default", "test")
	expectMissing[corev1.Service](t, fc, "operator-ns", metricsResourceName(shortName))
	// ServiceMonitor gets garbage collected when the Service is deleted - we cannot test that here.
}

func TestPathConflictDetection(t *testing.T) {
	tests := []struct {
		name           string
		newPath        string
		newPathType    networkingv1.PathType
		existingPaths  map[string]networkingv1.PathType
		expectConflict bool
		conflictPath   string
	}{
		{
			name:           "no conflict with different paths",
			newPath:        "/path1",
			newPathType:    networkingv1.PathTypePrefix,
			existingPaths:  map[string]networkingv1.PathType{"/path2": networkingv1.PathTypePrefix},
			expectConflict: false,
		},
		{
			name:           "conflict with prefix path",
			newPath:        "/parent/child",
			newPathType:    networkingv1.PathTypePrefix,
			existingPaths:  map[string]networkingv1.PathType{"/parent": networkingv1.PathTypePrefix},
			expectConflict: true,
			conflictPath:   "/parent",
		},
		{
			name:           "conflict with prefix path (reverse order)",
			newPath:        "/parent",
			newPathType:    networkingv1.PathTypePrefix,
			existingPaths:  map[string]networkingv1.PathType{"/parent/child": networkingv1.PathTypePrefix},
			expectConflict: true,
			conflictPath:   "/parent/child",
		},
		{
			name:           "conflict with exact path",
			newPath:        "/same-path",
			newPathType:    networkingv1.PathTypeExact,
			existingPaths:  map[string]networkingv1.PathType{"/same-path": networkingv1.PathTypeExact},
			expectConflict: true,
			conflictPath:   "/same-path",
		},
		{
			name:           "no conflict with different exact paths",
			newPath:        "/exact1",
			newPathType:    networkingv1.PathTypeExact,
			existingPaths:  map[string]networkingv1.PathType{"/exact2": networkingv1.PathTypeExact},
			expectConflict: false,
		},
		{
			name:           "no conflict between exact and prefix with different paths",
			newPath:        "/exact-path",
			newPathType:    networkingv1.PathTypeExact,
			existingPaths:  map[string]networkingv1.PathType{"/prefix-path": networkingv1.PathTypePrefix},
			expectConflict: false,
		},
		{
			name:           "conflict between exact and prefix with same path",
			newPath:        "/mixed-type",
			newPathType:    networkingv1.PathTypeExact,
			existingPaths:  map[string]networkingv1.PathType{"/mixed-type": networkingv1.PathTypePrefix},
			expectConflict: true,
			conflictPath:   "/mixed-type",
		},
		{
			name:           "root path does not conflict with other paths",
			newPath:        "/",
			newPathType:    networkingv1.PathTypePrefix,
			existingPaths:  map[string]networkingv1.PathType{"/some-path": networkingv1.PathTypePrefix},
			expectConflict: false,
		},
		{
			name:           "path normalization - empty path",
			newPath:        "",
			newPathType:    networkingv1.PathTypePrefix,
			existingPaths:  map[string]networkingv1.PathType{"/": networkingv1.PathTypePrefix},
			expectConflict: false,
		},
		{
			name:           "path normalization - missing leading slash",
			newPath:        "no-leading-slash",
			newPathType:    networkingv1.PathTypePrefix,
			existingPaths:  map[string]networkingv1.PathType{"/no-leading-slash": networkingv1.PathTypePrefix},
			expectConflict: true,
			conflictPath:   "/no-leading-slash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasConflict, conflictPath := checkPathConflict(tt.newPath, tt.newPathType, tt.existingPaths)
			if hasConflict != tt.expectConflict {
				t.Errorf("checkPathConflict() hasConflict = %v, want %v", hasConflict, tt.expectConflict)
			}
			if hasConflict && conflictPath != tt.conflictPath {
				t.Errorf("checkPathConflict() conflictPath = %v, want %v", conflictPath, tt.conflictPath)
			}
		})
	}
}

func TestHandlersForIngressWithConflictingPaths(t *testing.T) {
	// Create a test ingress with conflicting paths
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
			// Add a default backend for the root path
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "default-service",
					Port: networkingv1.ServiceBackendPort{Number: 8000},
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/parent",
									PathType: ptr.To(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "parent-service",
											Port: networkingv1.ServiceBackendPort{Number: 8080},
										},
									},
								},
								{
									Path:     "/parent/child",
									PathType: ptr.To(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "child-service",
											Port: networkingv1.ServiceBackendPort{Number: 8081},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Create fake client with services
	defaultService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.0",
			Ports:     []corev1.ServicePort{{Port: 8000}},
		},
	}

	parentService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "parent-service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.1",
			Ports:     []corev1.ServicePort{{Port: 8080}},
		},
	}

	childService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "child-service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.2",
			Ports:     []corev1.ServicePort{{Port: 8081}},
		},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(ing, defaultService, parentService, childService).
		Build()

	// Create a recorder to capture events
	recorder := &fakeRecorder{}

	// Create a logger
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	logger := zl.Sugar()

	// Call handlersForIngress
	handlers, err := handlersForIngress(context.Background(), ing, fc, recorder, "", logger)
	if err != nil {
		t.Fatalf("handlersForIngress() error = %v", err)
	}

	// Verify that handlers map contains paths
	// We should have 3 handlers: "/" (default), "/parent", and "/parent/child"
	// Even though there's a conflict, our implementation currently keeps both paths
	// and just issues a warning
	if len(handlers) != 3 {
		t.Errorf("Expected 3 handlers, got %d", len(handlers))
	}

	// Verify that the handlers map contains the expected paths
	if _, ok := handlers["/"]; !ok {
		t.Errorf("Expected handler for path \"/\" but it was not found")
	}

	if _, ok := handlers["/parent"]; !ok {
		t.Errorf("Expected handler for path \"/parent\" but it was not found")
	}

	if _, ok := handlers["/parent/child"]; !ok {
		t.Errorf("Expected handler for path \"/parent/child\" but it was not found")
	}

	// Verify that a warning event was recorded for the conflicting paths
	hasConflictEvent := false
	for _, event := range recorder.events {
		if event.eventType == corev1.EventTypeWarning && event.reason == "ConflictingPaths" {
			hasConflictEvent = true
			break
		}
	}

	if !hasConflictEvent {
		t.Errorf("Expected a ConflictingPaths warning event, but none was recorded")
	}
}

// fakeRecorder is a simple implementation of the EventRecorder interface for testing
type fakeRecorder struct {
	events []struct {
		object    interface{}
		eventType string
		reason    string
		message   string
	}
}

func (f *fakeRecorder) Event(object runtime.Object, eventType, reason, message string) {
	f.events = append(f.events, struct {
		object    interface{}
		eventType string
		reason    string
		message   string
	}{
		object:    object,
		eventType: eventType,
		reason:    reason,
		message:   message,
	})
}

func (f *fakeRecorder) Eventf(object runtime.Object, eventType, reason, messageFmt string, args ...interface{}) {
	var message string
	if len(args) > 0 {
		message = fmt.Sprintf(messageFmt, args...)
	} else {
		message = messageFmt
	}
	f.events = append(f.events, struct {
		object    interface{}
		eventType string
		reason    string
		message   string
	}{
		object:    object,
		eventType: eventType,
		reason:    reason,
		message:   message,
	})
}

func (f *fakeRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventType, reason, messageFmt string, args ...interface{}) {
	f.Eventf(object, eventType, reason, messageFmt, args...)
}

func TestIngressLetsEncryptStaging(t *testing.T) {
	cl := tstest.NewClock(tstest.ClockOpts{})
	zl := zap.Must(zap.NewDevelopment())

	pcLEStaging, pcLEStagingFalse, pcOther := proxyClassesForLEStagingTest()

	testCases := testCasesForLEStagingTests(pcLEStaging, pcLEStagingFalse, pcOther)

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme)

			builder = builder.WithObjects(pcLEStaging, pcLEStagingFalse, pcOther).
				WithStatusSubresource(pcLEStaging, pcLEStagingFalse, pcOther)

			fc := builder.Build()

			if tt.proxyClassPerResource != "" || tt.defaultProxyClass != "" {
				name := tt.proxyClassPerResource
				if name == "" {
					name = tt.defaultProxyClass
				}
				setProxyClassReady(t, fc, cl, name)
			}

			mustCreate(t, fc, ingressClass())
			mustCreate(t, fc, service())
			ing := ingress()
			if tt.proxyClassPerResource != "" {
				ing.Labels = map[string]string{
					LabelProxyClass: tt.proxyClassPerResource,
				}
			}
			mustCreate(t, fc, ing)

			ingR := &IngressReconciler{
				Client: fc,
				ssr: &tailscaleSTSReconciler{
					Client:            fc,
					tsClient:          &fakeTSClient{},
					tsnetServer:       &fakeTSNetServer{certDomains: []string{"test-host"}},
					defaultTags:       []string{"tag:test"},
					operatorNamespace: "operator-ns",
					proxyImage:        "tailscale/tailscale:test",
				},
				logger:            zl.Sugar(),
				defaultProxyClass: tt.defaultProxyClass,
			}

			expectReconciled(t, ingR, "default", "test")

			_, shortName := findGenName(t, fc, "default", "test", "ingress")
			sts := &appsv1.StatefulSet{}
			if err := fc.Get(context.Background(), client.ObjectKey{Namespace: "operator-ns", Name: shortName}, sts); err != nil {
				t.Fatalf("failed to get StatefulSet: %v", err)
			}

			if tt.useLEStagingEndpoint {
				verifyEnvVar(t, sts, "TS_DEBUG_ACME_DIRECTORY_URL", letsEncryptStagingEndpoint)
			} else {
				verifyEnvVarNotPresent(t, sts, "TS_DEBUG_ACME_DIRECTORY_URL")
			}
		})
	}
}

func ingressClass() *networkingv1.IngressClass {
	return &networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{Name: "tailscale"},
		Spec:       networkingv1.IngressClassSpec{Controller: "tailscale.com/ts-ingress"},
	}
}

func service() *corev1.Service {
	return &corev1.Service{
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
	}
}

func ingress() *networkingv1.Ingress {
	return &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
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
}
