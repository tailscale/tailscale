// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
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
		Client:           fc,
		ingressClassName: "tailscale",
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
		replicas:   ptr.To[int32](1),
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
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeResourceReqs)

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
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

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
		Client:           fc,
		ingressClassName: "tailscale",
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
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeResourceReqs)

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
			Pod:         &tsapi.Pod{Annotations: map[string]string{"foo.io/bar": "some-val"}},
		}},
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
		Client:           fc,
		ingressClassName: "tailscale",
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
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeResourceReqs)

	// 2. Ingress is updated to specify a ProxyClass, ProxyClass is not yet
	// ready, so proxy resource configuration does not change.
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		mak.Set(&ing.ObjectMeta.Labels, LabelAnnotationProxyClass, "custom-metadata")
	})
	expectReconciled(t, ingR, "default", "test")
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeResourceReqs)

	// 3. ProxyClass is set to Ready by proxy-class reconciler. Ingress get
	// reconciled and configuration from the ProxyClass is applied to the
	// created proxy resources.
	mustUpdateStatus(t, fc, "", "custom-metadata", func(pc *tsapi.ProxyClass) {
		pc.Status = tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassReady),
				ObservedGeneration: pc.Generation,
			}},
		}
	})
	expectReconciled(t, ingR, "default", "test")
	opts.proxyClass = pc.Name
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeResourceReqs)

	// 4. tailscale.com/proxy-class label is removed from the Ingress, the
	// Ingress gets reconciled and the custom ProxyClass configuration is
	// removed from the proxy resources.
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		delete(ing.ObjectMeta.Labels, LabelAnnotationProxyClass)
	})
	expectReconciled(t, ingR, "default", "test")
	opts.proxyClass = ""
	expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeResourceReqs)
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
			}},
		},
	}
	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: serviceMonitorCRD}}

	// Create fake client with ProxyClass, IngressClass, Ingress with metrics ProxyClass, and Service
	ing := ingress()
	ing.Labels = map[string]string{
		LabelAnnotationProxyClass: "metrics",
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
		Client:           fc,
		ingressClassName: "tailscale",
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

func TestIngressProxyClassAnnotation(t *testing.T) {
	cl := tstest.NewClock(tstest.ClockOpts{})
	zl := zap.Must(zap.NewDevelopment())

	pcLEStaging, pcLEStagingFalse, _ := proxyClassesForLEStagingTest()

	testCases := []struct {
		name                 string
		proxyClassAnnotation string
		proxyClassLabel      string
		proxyClassDefault    string
		expectedProxyClass   string
		expectEvents         []string
	}{
		{
			name:               "via_label",
			proxyClassLabel:    pcLEStaging.Name,
			expectedProxyClass: pcLEStaging.Name,
		},
		{
			name:                 "via_annotation",
			proxyClassAnnotation: pcLEStaging.Name,
			expectedProxyClass:   pcLEStaging.Name,
		},
		{
			name:               "via_default",
			proxyClassDefault:  pcLEStaging.Name,
			expectedProxyClass: pcLEStaging.Name,
		},
		{
			name:                 "via_label_override_annotation",
			proxyClassLabel:      pcLEStaging.Name,
			proxyClassAnnotation: pcLEStagingFalse.Name,
			expectedProxyClass:   pcLEStaging.Name,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme)

			builder = builder.WithObjects(pcLEStaging, pcLEStagingFalse).
				WithStatusSubresource(pcLEStaging, pcLEStagingFalse)

			fc := builder.Build()

			if tt.proxyClassAnnotation != "" || tt.proxyClassLabel != "" || tt.proxyClassDefault != "" {
				name := tt.proxyClassDefault
				if name == "" {
					name = tt.proxyClassLabel
					if name == "" {
						name = tt.proxyClassAnnotation
					}
				}
				setProxyClassReady(t, fc, cl, name)
			}

			mustCreate(t, fc, ingressClass())
			mustCreate(t, fc, service())
			ing := ingress()
			if tt.proxyClassLabel != "" {
				ing.Labels = map[string]string{
					LabelAnnotationProxyClass: tt.proxyClassLabel,
				}
			}
			if tt.proxyClassAnnotation != "" {
				ing.Annotations = map[string]string{
					LabelAnnotationProxyClass: tt.proxyClassAnnotation,
				}
			}
			mustCreate(t, fc, ing)

			ingR := &IngressReconciler{
				Client:           fc,
				ingressClassName: "tailscale",
				ssr: &tailscaleSTSReconciler{
					Client:            fc,
					tsClient:          &fakeTSClient{},
					tsnetServer:       &fakeTSNetServer{certDomains: []string{"test-host"}},
					defaultTags:       []string{"tag:test"},
					operatorNamespace: "operator-ns",
					proxyImage:        "tailscale/tailscale:test",
				},
				logger:            zl.Sugar(),
				defaultProxyClass: tt.proxyClassDefault,
			}

			expectReconciled(t, ingR, "default", "test")

			_, shortName := findGenName(t, fc, "default", "test", "ingress")
			sts := &appsv1.StatefulSet{}
			if err := fc.Get(context.Background(), client.ObjectKey{Namespace: "operator-ns", Name: shortName}, sts); err != nil {
				t.Fatalf("failed to get StatefulSet: %v", err)
			}

			switch tt.expectedProxyClass {
			case pcLEStaging.Name:
				verifyEnvVar(t, sts, "TS_DEBUG_ACME_DIRECTORY_URL", letsEncryptStagingEndpoint)
			case pcLEStagingFalse.Name:
				verifyEnvVarNotPresent(t, sts, "TS_DEBUG_ACME_DIRECTORY_URL")
			default:
				t.Fatalf("unexpected expected ProxyClass %q", tt.expectedProxyClass)
			}
		})
	}
}

func TestIngressLetsEncryptStaging(t *testing.T) {
	cl := tstest.NewClock(tstest.ClockOpts{})
	zl := zap.Must(zap.NewDevelopment())

	pcLEStaging, pcLEStagingFalse, pcOther := proxyClassesForLEStagingTest()

	testCases := testCasesForLEStagingTests()

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
					LabelAnnotationProxyClass: tt.proxyClassPerResource,
				}
			}
			mustCreate(t, fc, ing)

			ingR := &IngressReconciler{
				Client:           fc,
				ingressClassName: "tailscale",
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

func TestEmptyPath(t *testing.T) {
	testCases := []struct {
		name           string
		paths          []networkingv1.HTTPIngressPath
		expectedEvents []string
	}{
		{
			name: "empty_path_with_prefix_type",
			paths: []networkingv1.HTTPIngressPath{
				{
					PathType: ptrPathType(networkingv1.PathTypePrefix),
					Path:     "",
					Backend:  *backend(),
				},
			},
			expectedEvents: []string{
				"Normal PathUndefined configured backend is missing a path, defaulting to '/'",
			},
		},
		{
			name: "empty_path_with_implementation_specific_type",
			paths: []networkingv1.HTTPIngressPath{
				{
					PathType: ptrPathType(networkingv1.PathTypeImplementationSpecific),
					Path:     "",
					Backend:  *backend(),
				},
			},
			expectedEvents: []string{
				"Normal PathUndefined configured backend is missing a path, defaulting to '/'",
			},
		},
		{
			name: "empty_path_with_exact_type",
			paths: []networkingv1.HTTPIngressPath{
				{
					PathType: ptrPathType(networkingv1.PathTypeExact),
					Path:     "",
					Backend:  *backend(),
				},
			},
			expectedEvents: []string{
				"Warning UnsupportedPathTypeExact Exact path type strict matching is currently not supported and requests will be routed as for Prefix path type. This behaviour might change in the future.",
				"Normal PathUndefined configured backend is missing a path, defaulting to '/'",
			},
		},
		{
			name: "two_competing_but_not_identical_paths_including_one_empty",
			paths: []networkingv1.HTTPIngressPath{
				{
					PathType: ptrPathType(networkingv1.PathTypeImplementationSpecific),
					Path:     "",
					Backend:  *backend(),
				},
				{
					PathType: ptrPathType(networkingv1.PathTypeImplementationSpecific),
					Path:     "/",
					Backend:  *backend(),
				},
			},
			expectedEvents: []string{
				"Normal PathUndefined configured backend is missing a path, defaulting to '/'",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			fc := fake.NewFakeClient(ingressClass())
			ft := &fakeTSClient{}
			fr := record.NewFakeRecorder(3) // bump this if you expect a test case to throw more events
			fakeTsnetServer := &fakeTSNetServer{certDomains: []string{"foo.com"}}
			zl, err := zap.NewDevelopment()
			if err != nil {
				t.Fatal(err)
			}
			ingR := &IngressReconciler{
				recorder:         fr,
				Client:           fc,
				ingressClassName: "tailscale",
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
			mustCreate(t, fc, ingressWithPaths(tt.paths))
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
				hostname:   "foo",
				app:        kubetypes.AppIngressResource,
			}
			serveConfig := &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{"${TS_CERT_DOMAIN}:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: "http://1.2.3.4:8080/"}}}},
			}
			opts.serveConfig = serveConfig

			expectEqual(t, fc, expectedSecret(t, fc, opts))
			expectEqual(t, fc, expectedHeadlessService(shortName, "ingress"))
			expectEqual(t, fc, expectedSTSUserspace(t, fc, opts), removeResourceReqs)

			expectEvents(t, fr, tt.expectedEvents)
		})
	}
}

// ptrPathType is a helper function to return a pointer to the pathtype string (required for TestEmptyPath)
func ptrPathType(p networkingv1.PathType) *networkingv1.PathType {
	return &p
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
			UID:       "1234-UID",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
			DefaultBackend:   backend(),
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"default-test"}},
			},
		},
	}
}

func ingressWithPaths(paths []networkingv1.HTTPIngressPath) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "foo.tailnetxyz.ts.net",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: paths,
						},
					},
				},
			},
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"foo.tailnetxyz.ts.net"}},
			},
		},
	}
}

func backend() *networkingv1.IngressBackend {
	return &networkingv1.IngressBackend{
		Service: &networkingv1.IngressServiceBackend{
			Name: "test",
			Port: networkingv1.ServiceBackendPort{
				Number: 8080,
			},
		},
	}
}
