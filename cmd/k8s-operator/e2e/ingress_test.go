// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"tailscale.com/cmd/testwrapper/flakytest"
	kube "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
	"tailscale.com/util/httpm"
)

// See [TestMain] for test requirements.
func TestL3Ingress(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/corp/issues/37533")
	if tnClient == nil {
		t.Skip("TestIngress requires a working tailnet client")
	}

	// Apply nginx
	createAndCleanup(t, kubeClient, nginxDeployment("default", "nginx"))
	// Apply service to expose it as ingress
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
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
		maybeReadySvc := &corev1.Service{ObjectMeta: objectMeta("default", "test-ingress")}
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

	var resp *http.Response
	if err := tstest.WaitFor(time.Minute, func() error {
		// TODO(tomhjp): Get the tailnet DNS name from the associated secret instead.
		// If we are not the first tailnet node with the requested name, we'll get
		// a -N suffix.
		req, err := http.NewRequest(httpm.GET, fmt.Sprintf("http://%s-%s:80", svc.Namespace, svc.Name), nil)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		resp, err = tnClient.HTTPClient().Do(req.WithContext(ctx))
		return err
	}); err != nil {
		t.Fatalf("error trying to reach Service: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %v; response body s", resp.StatusCode)
	}
}

func TestL7HAIngress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestIngress requires a working tailnet client")
	}

	// Apply nginx Deployment and Service.
	createAndCleanup(t, kubeClient, nginxDeployment("default", "nginx"))
	createAndCleanup(t, kubeClient, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
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
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"tailscale.com/proxy-group": "ingress",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: new("tailscale"),
			TLS: []networkingv1.IngressTLS{
				networkingv1.IngressTLS{
					Hosts: []string{"test-ingress"},
				},
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
	createAndCleanup(t, kubeClient, ingress)

	t.Logf("Waiting for the Ingress to be ready...")
	time.Sleep(time.Hour)

	if err := tstest.WaitFor(time.Minute, func() error {
		maybeReadySvc := &corev1.Service{ObjectMeta: objectMeta("default", "test-ingress")}
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

	// var resp *http.Response
	// if err := tstest.WaitFor(time.Minute, func() error {
	// 	// TODO(tomhjp): Get the tailnet DNS name from the associated secret instead.
	// 	// If we are not the first tailnet node with the requested name, we'll get
	// 	// a -N suffix.
	// 	req, err := http.NewRequest(httpm.GET, fmt.Sprintf("http://%s-%s:80", svc.Namespace, svc.Name), nil)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	// 	defer cancel()
	// 	resp, err = tnClient.HTTPClient().Do(req.WithContext(ctx))
	// 	return err
	// }); err != nil {
	// 	t.Fatalf("error trying to reach Service: %v", err)
	// }

	// if resp.StatusCode != http.StatusOK {
	// 	t.Fatalf("unexpected status: %v; response body s", resp.StatusCode)
	// }
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
