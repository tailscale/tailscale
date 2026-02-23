// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"tailscale.com/cmd/testwrapper/flakytest"
	kube "tailscale.com/k8s-operator"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
	"tailscale.com/util/httpm"
)

// See [TestMain] for test requirements.
func TestIngress(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/corp/issues/37533")
	if tnClient == nil {
		t.Skip("TestIngress requires a working tailnet client")
	}

	// Apply nginx
	createAndCleanup(t, kubeClient,
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

	// TODO(tomhjp): Delete once we've reproduced the flake with this extra info.
	t0 := time.Now()
	watcherCtx, cancelWatcher := context.WithCancel(t.Context())
	defer cancelWatcher()
	go func() {
		// client-go client for logs.
		clientGoKubeClient, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			t.Logf("error creating client-go Kubernetes client: %v", err)
			return
		}

		for {
			select {
			case <-watcherCtx.Done():
				t.Logf("stopping watcher after %v", time.Since(t0))
				return
			case <-time.After(time.Minute):
				t.Logf("dumping info after %v elapsed", time.Since(t0))
				// Service itself.
				svc := &corev1.Service{ObjectMeta: objectMeta("default", "test-ingress")}
				err := get(watcherCtx, kubeClient, svc)
				svcYaml, _ := yaml.Marshal(svc)
				t.Logf("Service: %s, error: %v\n%s", svc.Name, err, string(svcYaml))

				// Pods in tailscale namespace.
				var pods corev1.PodList
				if err := kubeClient.List(watcherCtx, &pods, client.InNamespace("tailscale")); err != nil {
					t.Logf("error listing Pods in tailscale namespace: %v", err)
				} else {
					t.Logf("%d Pods", len(pods.Items))
					for _, pod := range pods.Items {
						podYaml, _ := yaml.Marshal(pod)
						t.Logf("Pod: %s\n%s", pod.Name, string(podYaml))
						logs := clientGoKubeClient.CoreV1().Pods("tailscale").GetLogs(pod.Name, &corev1.PodLogOptions{}).Do(watcherCtx)
						logData, err := logs.Raw()
						if err != nil {
							t.Logf("error reading logs for Pod %s: %v", pod.Name, err)
							continue
						}
						t.Logf("Logs for Pod %s:\n%s", pod.Name, string(logData))
					}
				}

				// Tailscale status on the tailnet.
				lc, err := tnClient.LocalClient()
				if err != nil {
					t.Logf("error getting tailnet local client: %v", err)
				} else {
					status, err := lc.Status(watcherCtx)
					statusJSON, _ := json.MarshalIndent(status, "", "  ")
					t.Logf("Tailnet status: %s, error: %v", string(statusJSON), err)
				}
			}
		}
	}()

	// TODO: instead of timing out only when test times out, cancel context after 60s or so.
	if err := wait.PollUntilContextCancel(t.Context(), time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		if time.Since(t0) > time.Minute {
			t.Logf("%v elapsed waiting for Service default/test-ingress to become Ready", time.Since(t0))
		}
		maybeReadySvc := &corev1.Service{ObjectMeta: objectMeta("default", "test-ingress")}
		if err := get(ctx, kubeClient, maybeReadySvc); err != nil {
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
	cancelWatcher()

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
