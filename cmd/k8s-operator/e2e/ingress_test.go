// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/client/tailscale/v2"
	kube "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/util/httpm"
)

// See [TestMain] for test requirements.
func TestL3Ingress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestL3Ingress requires a working tailnet client")
	}
	t.Parallel()

	// Apply nginx
	nginx := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, nginx)

	// Singleton ingress proxy forwards only the Service's primary ClusterIP family,
	// Dualstack isn't supported.
	for _, tc := range []struct {
		name     string
		families []corev1.IPFamily
	}{
		{"IPv4", []corev1.IPFamily{corev1.IPv4Protocol}},
		{"IPv6", []corev1.IPFamily{corev1.IPv6Protocol}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireClusterFamilies(t, tc.families)
			svc := exposeIngressService(nginx.Name, tc.families...)
			createAndCleanup(t, kubeClient, svc)
			waitForServiceReady(t, svc.Name)
			proxyIP := proxyDeviceIP(t, svc.Name)
			if err := testIngressIsReachable(t, newHTTPClient(tnClient), "http://"+net.JoinHostPort(proxyIP, "80")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// exposeIngressService returns a Service for the given IP families that exposes nginx
// using a singleton ingress proxy.
func exposeIngressService(nginxName string, families ...corev1.IPFamily) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("test-ingress"),
			Namespace: ns,
			Annotations: map[string]string{
				"tailscale.com/expose": "true",
			},
		},
		Spec: corev1.ServiceSpec{
			IPFamilyPolicy: new(ipFamilyPolicy(families)),
			IPFamilies:     families,
			Selector: map[string]string{
				"app.kubernetes.io/name": nginxName,
			},
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: "TCP",
					Port:     80,
				},
			},
		},
	}
}

// TODO(beckypauley): this duplicates logic in in waitForEgress - consider merging
// both into a waitForServiceCondition function.
func waitForServiceReady(t *testing.T, svcName string) {
	t.Helper()
	if err := tstest.WaitFor(time.Minute, func() error {
		maybeReadySvc := &corev1.Service{ObjectMeta: objectMeta(ns, svcName)}
		if err := get(t.Context(), kubeClient, maybeReadySvc); err != nil {
			return err
		}
		isReady := kube.SvcIsReady(maybeReadySvc)
		if isReady {
			t.Log("Service is ready")
			return nil
		}
		return fmt.Errorf("Service is not ready yet")
	}); err != nil {
		t.Fatalf("error waiting for the Service to become Ready: %v", err)
	}
}

// proxyDeviceIP returns the proxy device IP matching the family of the named
// Service's primary ClusterIP, read from the proxy's state Secret.
func proxyDeviceIP(t *testing.T, svcName string) string {
	t.Helper()
	var proxyIP string
	if err := tstest.WaitFor(time.Minute, func() error {
		var secrets corev1.SecretList
		if err := kubeClient.List(t.Context(), &secrets,
			client.InNamespace("tailscale"),
			client.MatchingLabels{
				"tailscale.com/parent-resource":    svcName,
				"tailscale.com/parent-resource-ns": ns,
			},
		); err != nil {
			return err
		}
		if len(secrets.Items) == 0 {
			return fmt.Errorf("Service not ready yet")
		}
		var deviceIPs []string
		if err := json.Unmarshal(secrets.Items[0].Data[kubetypes.KeyDeviceIPs], &deviceIPs); err != nil {
			return fmt.Errorf("decoding device IPs: %w", err)
		}
		currentSvc := &corev1.Service{ObjectMeta: objectMeta(ns, svcName)}
		if err := get(t.Context(), kubeClient, currentSvc); err != nil {
			return err
		}
		proxyIP = ipMatchingFamily(deviceIPs, currentSvc.Spec.ClusterIP)
		if proxyIP == "" {
			return fmt.Errorf("device has no IP for %s family", currentSvc.Spec.ClusterIP)
		}
		return nil
	}); err != nil {
		t.Fatalf("error waiting for matching-family IP for Service: %v", err)
	}
	return proxyIP
}

func TestL3HAIngress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestL3HAIngress requires a working tailnet client")
	}
	t.Parallel()

	// Apply nginx.
	nginx := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, nginx)

	// Create an ingress ProxyGroup.
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("ingress"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeIngress,
		},
	}
	createAndCleanup(t, kubeClient, pg)

	for _, tc := range []struct {
		name     string
		families []corev1.IPFamily
	}{
		{"IPv4", []corev1.IPFamily{corev1.IPv4Protocol}},
		{"IPv6", []corev1.IPFamily{corev1.IPv6Protocol}},
		{"DualStack", []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireClusterFamilies(t, tc.families)
			svc := exposeHAIngressService(pg.Name, nginx.Name, tc.families...)
			createAndCleanup(t, kubeClient, svc)
			for _, svcIP := range waitForHAIngressServiceIPs(t, svc.Name) {
				if err := testIngressIsReachable(t, newHTTPClient(tnClient), "http://"+net.JoinHostPort(svcIP, "80")); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// exposeHAIngressService returns a Service of the given IP families that exposes
// nginx via a ProxyGroup.
func exposeHAIngressService(pgName, nginxName string, families ...corev1.IPFamily) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("test-ingress"),
			Namespace: ns,
			Annotations: map[string]string{
				"tailscale.com/proxy-group": pgName,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: new("tailscale"),
			IPFamilyPolicy:    new(ipFamilyPolicy(families)),
			IPFamilies:        families,
			Selector: map[string]string{
				"app.kubernetes.io/name": nginxName,
			},
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: "TCP",
					Port:     80,
				},
			},
		},
	}
}

// waitForHAIngressServiceIPs waits until the named HA ingress Service is
// configured and returns the Tailscale Service address for each of its ClusterIP
// families.
func waitForHAIngressServiceIPs(t *testing.T, svcName string) []string {
	t.Helper()
	var svcIPs []string
	forceReconcile := triggerReconcile(t,
		client.ObjectKey{Namespace: ns, Name: svcName},
		&corev1.Service{}, 30*time.Second)

	// Wait for Service to be ready
	if err := tstest.WaitFor(5*time.Minute, func() error {
		maybeReadySvc := &corev1.Service{ObjectMeta: objectMeta(ns, svcName)}
		forceReconcile()
		if err := get(t.Context(), kubeClient, maybeReadySvc); err != nil {
			return err
		}
		for _, cond := range maybeReadySvc.Status.Conditions {
			if cond.Type == string(tsapi.IngressSvcConfigured) && cond.Status == metav1.ConditionTrue {
				if len(maybeReadySvc.Status.LoadBalancer.Ingress) == 0 {
					return fmt.Errorf("Service does not have an IP assigned yet")
				}
				tsSvc, err := tsClient.VIPServices().Get(t.Context(), "svc:default-"+svcName)
				if err != nil {
					return fmt.Errorf("getting Tailscale Service: %w", err)
				}
				ips := make([]string, 0, len(maybeReadySvc.Spec.ClusterIPs))
				for _, clusterIP := range maybeReadySvc.Spec.ClusterIPs {
					ip := ipMatchingFamily(tsSvc.Addrs, clusterIP)
					if ip == "" {
						return fmt.Errorf("Tailscale Service has no IP matching Kubernetes ClusterIP %s family", clusterIP)
					}
					ips = append(ips, ip)
				}
				svcIPs = ips
				t.Log("Service is ready")
				return nil
			}
		}
		return fmt.Errorf("Service is not ready yet")
	}); err != nil {
		t.Fatalf("error waiting for the Service to become ready: %v", err)
	}
	return svcIPs
}

func TestL7Ingress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestL7Ingress requires a working tailnet client")
	}
	t.Parallel()

	// Apply nginx Deployment and Service.
	nginx := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, nginx)

	for _, tc := range []struct {
		name     string
		families []corev1.IPFamily
	}{
		{"IPv4", []corev1.IPFamily{corev1.IPv4Protocol}},
		{"IPv6", []corev1.IPFamily{corev1.IPv6Protocol}},
		{"DualStack", []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireClusterFamilies(t, tc.families)
			backend := l7BackendService(nginx.Name, tc.families...)
			createAndCleanup(t, kubeClient, backend)
			hostname := exposeL7Ingress(t, backend.Name, nil)
			if err := testIngressIsReachable(t, newHTTPClient(tnClient), fmt.Sprintf("https://%s:443", hostname)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// l7BackendService returns a Service of the given families that fronts nginx as
// the backend for an L7 Ingress.
func l7BackendService(nginxName string, families ...corev1.IPFamily) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("test-nginx"),
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			IPFamilyPolicy: new(ipFamilyPolicy(families)),
			IPFamilies:     families,
			Selector: map[string]string{
				"app.kubernetes.io/name": nginxName,
			},
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 80,
				},
			},
		},
	}
}

// exposeL7Ingress creates an L7 Ingress (with the given annotations) for the named
// backend Service and returns its MagicDNS hostname once ready.
func exposeL7Ingress(t *testing.T, backendName string, annotations map[string]string) string {
	t.Helper()
	ingress := l7Ingress(ns, backendName, annotations)
	createAndCleanup(t, kubeClient, ingress)

	t.Log("Waiting for the Ingress to be ready...")
	hostname, err := waitForIngressHostname(t, ns, ingress.Name)
	if err != nil {
		t.Fatalf("error waiting for Ingress hostname: %v", err)
	}
	return hostname
}

func TestL7IngressDNSConfig(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestL7IngressDNSConfig requires a working tailnet client")
	}
	t.Parallel()

	nginx := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, nginx)
	createAndCleanup(t, kubeClient, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nginx.Name,
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name": nginx.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 80,
				},
			},
		},
	})

	ingress := l7Ingress(ns, nginx.Name, map[string]string{
		"tailscale.com/experimental-forward-cluster-traffic-via-ingress": "true",
	})
	createAndCleanup(t, kubeClient, ingress)
	hostname, err := waitForIngressHostname(t, ns, ingress.Name)
	if err != nil {
		t.Fatalf("error waiting for Ingress hostname: %v", err)
	}
	requireTargetIsReachable(t, fmt.Sprintf("https://%s:443", hostname))
}

func TestL7HAIngress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestL7HAIngress requires a working tailnet client")
	}
	t.Parallel()

	// Apply nginx Deployment.
	nginx := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, nginx)

	// Create ProxyGroup that the Ingress will reference.
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("ingress"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeIngress,
		},
	}
	createAndCleanup(t, kubeClient, pg)

	for _, tc := range []struct {
		name     string
		families []corev1.IPFamily
	}{
		{"IPv4", []corev1.IPFamily{corev1.IPv4Protocol}},
		{"IPv6", []corev1.IPFamily{corev1.IPv6Protocol}},
		{"DualStack", []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireClusterFamilies(t, tc.families)
			backend := l7BackendService(nginx.Name, tc.families...)
			createAndCleanup(t, kubeClient, backend)
			hostname := exposeL7Ingress(t, backend.Name, map[string]string{"tailscale.com/proxy-group": pg.Name})
			if err := testIngressIsReachable(t, newHTTPClient(tnClient), fmt.Sprintf("https://%s:443", hostname)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestL7HAIngressMultiTailnet(t *testing.T) {
	if tnClient == nil || secondTNClient == nil {
		t.Skip("TestL7HAIngressMultiTailnet requires a working tailnet client for a first and second tailnet")
	}
	t.Parallel()

	// Apply nginx Deployment and Service.
	nginx := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, nginx)
	createAndCleanup(t, kubeClient, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nginx.Name,
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name": nginx.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 80,
				},
			},
		},
	})

	// Create Ingress ProxyGroup for each Tailnet.
	firstTailnetPG := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("first-tailnet"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeIngress,
		},
	}
	createAndCleanup(t, kubeClient, firstTailnetPG)
	secondTailnetPG := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("second-tailnet"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:    tsapi.ProxyGroupTypeIngress,
			Tailnet: "second-tailnet",
		},
	}
	createAndCleanup(t, kubeClient, secondTailnetPG)

	if err := verifyProxyGroupTailnet(t, firstTailnetPG, tnClient); err != nil {
		t.Fatalf("verifying ProxyGroup %s is registered to the correct tailnet: %v", firstTailnetPG.Name, err)
	}
	if err := verifyProxyGroupTailnet(t, secondTailnetPG, secondTNClient); err != nil {
		t.Fatalf("verifying ProxyGroup %s is registered to the correct tailnet: %v", secondTailnetPG.Name, err)
	}

	// Apply Ingress to expose nginx.
	ingress := l7Ingress(ns, nginx.Name, map[string]string{
		"tailscale.com/proxy-group": secondTailnetPG.Name,
	})
	createAndCleanup(t, kubeClient, ingress)

	// Check that the tailscale (VIP) Service has been created in the expected Tailnet.
	svcName := "svc:" + ingress.Name
	if err := tstest.WaitFor(3*time.Minute, func() error {
		_, err := secondTSClient.VIPServices().Get(t.Context(), svcName)
		if tailscale.IsNotFound(err) {
			return fmt.Errorf("Tailscale service %q not yet in expected tailnet", svcName)
		}
		return err
	}); err != nil {
		t.Fatalf("Tailscale service %q never appeared in expected tailnet: %v", svcName, err)
	}
	hostname, err := waitForIngressHostname(t, ns, ingress.Name)
	if err != nil {
		t.Fatalf("error waiting for Ingress hostname: %v", err)
	}
	if err := testIngressIsReachable(t, newHTTPClient(secondTNClient), fmt.Sprintf("https://%s:443", hostname)); err != nil {
		t.Fatal(err)
	}
}

func l7Ingress(namespace, svc string, annotations map[string]string) *networkingv1.Ingress {
	name := generateName("test-ingress")
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: new("tailscale"),
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{name}},
			},
			Rules: []networkingv1.IngressRule{
				{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: new(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: svc,
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
											},
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
	return ingress
}

func nginxDeployment(namespace string) *appsv1.Deployment {
	name := generateName("nginx")
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": name,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name": name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name": name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx",
						},
					},
				},
			},
		},
	}
}

// triggerReconcile triggers an expected reconcile for the given object if
// none occurs. This is needed when running some tests against devcontrol,
// where the final change that should trigger a reconcile does not always do so.
// This has not been reproducible in a real tailnet environment, so a
// workaround that runs only when using devcontrol is acceptable.
func triggerReconcile(t testing.TB, key client.ObjectKey, obj client.Object, after time.Duration) func() {
	if !*fDevcontrol {
		return func() {}
	}
	triggerAt := time.Now().Add(after)
	var triggered bool
	return func() {
		if triggered || !time.Now().After(triggerAt) {
			return
		}
		if err := kubeClient.Get(t.Context(), key, obj); err != nil {
			t.Logf("failed to get %s: %v", key, err)
			return
		}
		ann := obj.GetAnnotations()
		if ann == nil {
			ann = map[string]string{}
		}
		ann["tailscale.com/trigger-reconcile"] = "true"
		obj.SetAnnotations(ann)
		if err := kubeClient.Update(t.Context(), obj); err != nil {
			t.Logf("failed to update %s: %v", key, err)
			return
		}
		triggered = true
	}
}

func ipMatchingFamily(ips []string, target string) string {
	targetIP, err := netip.ParseAddr(target)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err == nil && addr.Is4() == targetIP.Is4() {
			return ip
		}
	}
	return ""
}

// ipFamilyPolicy returns the IPFamilyPolicy for the requested families:
// RequireDualStack when both families are requested, SingleStack otherwise.
func ipFamilyPolicy(families []corev1.IPFamily) corev1.IPFamilyPolicy {
	if len(families) > 1 {
		return corev1.IPFamilyPolicyRequireDualStack
	}
	return corev1.IPFamilyPolicySingleStack
}

// requireClusterFamilies skips the test if the cluster supdoes not support the IP family being tested.
func requireClusterFamilies(t *testing.T, families []corev1.IPFamily) {
	t.Helper()
	for _, f := range families {
		if f == corev1.IPv4Protocol && !clusterIPv4Support {
			t.Skipf("cluster does not support %s", f)
		}
		if f == corev1.IPv6Protocol && !clusterIPv6Support {
			t.Skipf("cluster does not support %s", f)
		}
	}
}

func testIngressIsReachable(t *testing.T, httpClient *http.Client, url string) error {
	t.Helper()
	var resp *http.Response
	if err := tstest.WaitFor(3*time.Minute, func() error {
		req, err := http.NewRequest(httpm.GET, url, nil)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		resp, err = httpClient.Do(req.WithContext(ctx))
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}); err != nil {
		return fmt.Errorf("error trying to reach %s: %w", url, err)
	}
	return nil
}

func waitForIngressHostname(t *testing.T, namespace, name string) (string, error) {
	t.Helper()
	var hostname string
	forceReconcile := triggerReconcile(t,
		client.ObjectKey{Namespace: namespace, Name: name},
		&networkingv1.Ingress{}, 30*time.Second)

	if err := tstest.WaitFor(5*time.Minute, func() error {
		forceReconcile()
		ing := &networkingv1.Ingress{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{
			Namespace: namespace, Name: name,
		}, ing); err != nil {
			return err
		}
		if len(ing.Status.LoadBalancer.Ingress) == 0 ||
			ing.Status.LoadBalancer.Ingress[0].Hostname == "" {
			return fmt.Errorf("Ingress not ready yet")
		}
		hostname = ing.Status.LoadBalancer.Ingress[0].Hostname
		t.Log("Ingress is ready")
		return nil
	}); err != nil {
		return "", fmt.Errorf("Ingress %s/%s never got a hostname: %w", namespace, name, err)
	}
	return hostname, nil
}
