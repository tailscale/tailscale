// Copyright (c) Tailscale Inc & AUTHORS
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	kube "tailscale.com/k8s-operator"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
	"tailscale.com/util/httpm"
)

// See [TestMain] for test requirements.
func TestIngress(t *testing.T) {
	if apiClient == nil {
		t.Skip("TestIngress requires TS_API_CLIENT_SECRET set")
	}

	cfg := config.GetConfigOrDie()
	cl, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Apply nginx
	createAndCleanup(t, cl,
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx",
				Namespace: "default",
				Labels: map[string]string{
					"app.kubernetes.io/name": "nginx",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To[int32](1),
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
		})
	// Apply service to expose it as ingress
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"tailscale.com/expose":      "true",
				"tailscale.com/proxy-class": "prod",
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
	createAndCleanup(t, cl, svc)

	// TODO: instead of timing out only when test times out, cancel context after 60s or so.
	if err := wait.PollUntilContextCancel(t.Context(), time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		maybeReadySvc := &corev1.Service{ObjectMeta: objectMeta("default", "test-ingress")}
		if err := get(ctx, cl, maybeReadySvc); err != nil {
			return false, err
		}
		isReady := kube.SvcIsReady(maybeReadySvc)
		if isReady {
			t.Log("Service is ready")
		}
		return isReady, nil
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
		resp, err = tailnetClient.HTTPClient().Do(req.WithContext(ctx))
		return err
	}); err != nil {
		t.Fatalf("error trying to reach Service: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %v; response body s", resp.StatusCode)
	}
}
