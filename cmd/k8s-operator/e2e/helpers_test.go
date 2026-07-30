// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
)

const egressPort = 80

func generateName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, strings.ToLower(rand.Text()))
}

func egressService(name string, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     egressPort,
				},
			},
		},
	}
}

func egressURL(svcName string) string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svcName, ns, egressPort)
}

func waitForEgress(t *testing.T, svcName string, ready func(*corev1.Service) bool) {
	t.Helper()
	if err := tstest.WaitFor(5*time.Minute, func() error {
		svc := &corev1.Service{ObjectMeta: objectMeta(ns, svcName)}
		if err := get(t.Context(), kubeClient, svc); err != nil {
			return err
		}
		if ready(svc) {
			t.Logf("Service %s is ready", svcName)
			return nil
		}
		return fmt.Errorf("Service %s is not ready yet", svcName)
	}); err != nil {
		t.Fatalf("error waiting for Service %s to become ready: %v", svcName, err)
	}
}

func testEgressIsReachable(t *testing.T, url string) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("curl"),
			Namespace: ns,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:  "curl",
					Image: "curlimages/curl",
					Command: []string{"sh", "-c", fmt.Sprintf(
						`for i in $(seq 1 30); do `+
							`code=$(curl -s -o /dev/null -w "%%{http_code}" --max-time 5 %q); `+
							`[ "$code" = "200" ] && exit 0; sleep 3; done; exit 1`, url)},
				},
			},
		},
	}
	createAndCleanup(t, kubeClient, pod)

	// Budget is sized for the slowest caller (in-cluster MagicDNS, which waits on
	// the cluster resolver picking up the ts.net stub: kubelet ConfigMap
	// propagation into the CoreDNS pod, ~60-90s, plus a CoreDNS reload, ~30-45s).
	// Egress callers succeed on the first iteration, so the larger budget only
	// costs wall-clock on genuine failures.
	if err := tstest.WaitFor(4*time.Minute, func() error {
		p := &corev1.Pod{ObjectMeta: objectMeta(ns, pod.Name)}
		if err := get(t.Context(), kubeClient, p); err != nil {
			return err
		}
		if p.Status.Phase == corev1.PodSucceeded {
			t.Logf("curl pod %s succeeded", pod.Name)
			return nil
		}
		return fmt.Errorf("curl pod %s phase: %s", pod.Name, p.Status.Phase)
	}); err != nil {
		t.Fatalf("%s not reachable in-cluster: %v", url, err)
	}
}

// newHTTPClient returns a HTTP client for the given tailnet client.
// When running against devcontrol, trusts Pebble testCAs.
func newHTTPClient(cl *tsnet.Server) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: testCAs},
			DialContext:     cl.Dial,
		},
	}
}

// verifyProxyGroupTailnet verifies that a ProxyGroup is registered to the correct tailnet.
// This is done by getting the expected tailnet domain for the tailnet client,
// and comparing this with the actual device fqdn in the ProxyGroup state secret.
func verifyProxyGroupTailnet(t *testing.T, pg *tsapi.ProxyGroup, cl *tsnet.Server) error {
	t.Helper()
	// Determine the expected tailnet Magic DNS Name.
	lc, err := cl.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(t.Context())
	if err != nil {
		return err
	}
	_, expectedTailnet, ok := strings.Cut(strings.TrimSuffix(status.Self.DNSName, "."), ".")
	if !ok {
		return fmt.Errorf("unexpected DNSName format %q", status.Self.DNSName)
	}
	// Read the device FQDN from the first state secret for the ProxyGroup,
	// and verify that this matches the expected tailnet.
	if err := tstest.WaitFor(3*time.Minute, func() error {
		var secrets corev1.SecretList
		if err := kubeClient.List(t.Context(), &secrets,
			client.InNamespace("tailscale"),
			client.MatchingLabels{
				kubetypes.LabelSecretType:            kubetypes.LabelSecretTypeState,
				"tailscale.com/parent-resource-type": "proxygroup",
				"tailscale.com/parent-resource":      pg.Name,
			},
		); err != nil {
			return err
		}
		if len(secrets.Items) == 0 {
			return fmt.Errorf("no state secrets found for ProxyGroup %q yet", pg.Name)
		}
		fqdn := strings.TrimSuffix(string(secrets.Items[0].Data[kubetypes.KeyDeviceFQDN]), ".")
		_, tailnet, ok := strings.Cut(fqdn, ".")
		if !ok {
			return fmt.Errorf("ProxyGroup %q: device FQDN %q has no domain yet", pg.Name, fqdn)
		}
		if tailnet != expectedTailnet {
			return fmt.Errorf("ProxyGroup %q on wrong tailnet: got domain %q, want %q", pg.Name, tailnet, expectedTailnet)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("ProxyGroup %q not on expected tailnet: %v", pg.Name, err)
	}
	return nil
}
