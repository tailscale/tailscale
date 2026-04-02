// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

	// Apply nginx
	createAndCleanup(t, kubeClient, nginxDeployment(ns, "nginx"))
	// Apply service to expose it as ingress
	name := generateName("test-ingress")
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Annotations: map[string]string{
				"tailscale.com/expose": "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name": "nginx",
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
	createAndCleanup(t, kubeClient, svc)

	if err := tstest.WaitFor(time.Minute, func() error {
		maybeReadySvc := &corev1.Service{ObjectMeta: objectMeta(ns, name)}
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

	// Get the DNS name for the Service from the associated Secret.
	var fqdn string
	if err := tstest.WaitFor(time.Minute, func() error {
		var secrets corev1.SecretList
		if err := kubeClient.List(t.Context(), &secrets,
			client.InNamespace("tailscale"),
			client.MatchingLabels{
				"tailscale.com/parent-resource":    name,
				"tailscale.com/parent-resource-ns": ns,
			},
		); err != nil {
			return err
		}
		if len(secrets.Items) == 0 {
			return fmt.Errorf("Service not ready yet")
		}
		fqdn = strings.TrimSuffix(string(secrets.Items[0].Data[kubetypes.KeyDeviceFQDN]), ".")
		if fqdn != "" {
			t.Log("Got DNS name for Service")
			return nil
		}
		return fmt.Errorf("device FQDN not set yet")
	}); err != nil {
		t.Fatalf("error waiting for DNS Name for Service: %v", err)
	}

	if err := testIngressIsReachable(t, newHTTPClient(tnClient), fmt.Sprintf("http://%s:80", fqdn)); err != nil {
		t.Fatal(err)
	}
}

func TestL3HAIngress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestL3HAIngress requires a working tailnet client")
	}

	// Apply nginx.
	createAndCleanup(t, kubeClient, nginxDeployment(ns, "nginx"))

	// Create an ingress ProxyGroup.
	createAndCleanup(t, kubeClient, &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ingress",
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeIngress,
		},
	})

	// Apply a Service to expose nginx via the ProxyGroup.
	name := generateName("test-ingress")
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Annotations: map[string]string{
				"tailscale.com/proxy-group": "ingress",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: new("tailscale"),
			Selector: map[string]string{
				"app.kubernetes.io/name": "nginx",
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
	createAndCleanup(t, kubeClient, svc)

	var svcIPv4 string
	forceReconcile := triggerReconcile(t,
		client.ObjectKey{Namespace: ns, Name: name},
		&corev1.Service{}, 30*time.Second)

	// Wait for Service to be ready
	if err := tstest.WaitFor(5*time.Minute, func() error {
		maybeReadySvc := &corev1.Service{ObjectMeta: objectMeta(ns, name)}
		forceReconcile()
		if err := get(t.Context(), kubeClient, maybeReadySvc); err != nil {
			return err
		}
		for _, cond := range maybeReadySvc.Status.Conditions {
			if cond.Type == string(tsapi.IngressSvcConfigured) && cond.Status == metav1.ConditionTrue {
				if len(maybeReadySvc.Status.LoadBalancer.Ingress) == 0 {
					return fmt.Errorf("Service does not have an IP assigned yet")
				}
				svcIPv4 = maybeReadySvc.Status.LoadBalancer.Ingress[0].IP
				t.Log("Service is ready")
				return nil
			}
		}
		return fmt.Errorf("Service is not ready yet")
	}); err != nil {
		t.Fatalf("error waiting for the Service to become ready: %v", err)
	}

	if err := testIngressIsReachable(t, newHTTPClient(tnClient), fmt.Sprintf("http://%s:80", svcIPv4)); err != nil {
		t.Fatal(err)
	}
}

func TestL7Ingress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestL7Ingress requires a working tailnet client")
	}

	// Apply nginx Deployment and Service.
	createAndCleanup(t, kubeClient, nginxDeployment(ns, "nginx"))
	createAndCleanup(t, kubeClient, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name": "nginx",
			},
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 80,
				},
			},
		},
	})

	// Apply Ingress to expose nginx.
	name := generateName("test-ingress")
	ingress := l7Ingress(ns, name, map[string]string{})
	createAndCleanup(t, kubeClient, ingress)

	t.Log("Waiting for the Ingress to be ready...")

	hostname, err := waitForIngressHostname(t, ns, name)
	if err != nil {
		t.Fatalf("error waiting for Ingress hostname: %v", err)
	}

	if err := testIngressIsReachable(t, newHTTPClient(tnClient), fmt.Sprintf("https://%s:443", hostname)); err != nil {
		t.Fatal(err)
	}
}

func TestL7HAIngress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestL7HAIngress requires a working tailnet client")
	}

	// Apply nginx Deployment and Service.
	createAndCleanup(t, kubeClient, nginxDeployment(ns, "nginx"))
	createAndCleanup(t, kubeClient, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name": "nginx",
			},
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 80,
				},
			},
		},
	})

	// Create ProxyGroup that the Ingress will reference.
	createAndCleanup(t, kubeClient, &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ingress",
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeIngress,
		},
	})

	// Apply Ingress to expose nginx.
	name := generateName("test-ingress")
	ingress := l7Ingress(ns, name, map[string]string{"tailscale.com/proxy-group": "ingress"})
	createAndCleanup(t, kubeClient, ingress)

	t.Log("Waiting for the Ingress to be ready...")

	hostname, err := waitForIngressHostname(t, ns, name)
	if err != nil {
		t.Fatalf("error waiting for Ingress hostname: %v", err)
	}

	if err := testIngressIsReachable(t, newHTTPClient(tnClient), fmt.Sprintf("https://%s:443", hostname)); err != nil {
		t.Fatal(err)
	}
}

func l7Ingress(namespace, name string, annotations map[string]string) *networkingv1.Ingress {
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
											Name: "nginx",
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

func nginxDeployment(namespace, name string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "nginx",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name": "nginx",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name": "nginx",
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

func testIngressIsReachable(t *testing.T, httpClient *http.Client, url string) error {
	t.Helper()
	var resp *http.Response
	if err := tstest.WaitFor(time.Minute, func() error {
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
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from %s: %d", url, resp.StatusCode)
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
