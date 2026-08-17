// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
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
	"tailscale.com/client/tailscale/v2"
	"tailscale.com/ipn/store/mem"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
)

func generateName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, strings.ToLower(rand.Text()))
}

func requireTargetIsReachable(t *testing.T, url string) {
	t.Helper()

	volumes, mounts, cacertFlag := certVolumesForURL(url)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("curl"),
			Namespace: ns,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Volumes:       volumes,
			Containers: []corev1.Container{
				{
					Name:         "curl",
					Image:        "curlimages/curl",
					VolumeMounts: mounts,
					Command: []string{"sh", "-c", fmt.Sprintf(
						`for i in $(seq 1 40); do `+
							`code=$(curl -s %s-o /dev/null -w "%%{http_code}" --max-time 5 %q); `+
							`[ "$code" = "200" ] && exit 0; sleep 2; done; exit 1`, cacertFlag, url)},
				},
			},
		},
	}
	createAndCleanup(t, kubeClient, pod)

	if err := tstest.WaitFor(5*time.Minute, func() error {
		p := &corev1.Pod{ObjectMeta: objectMeta(ns, pod.Name)}
		if err := get(t.Context(), kubeClient, p); err != nil {
			return err
		}
		if p.Status.Phase == corev1.PodSucceeded {
			t.Logf("curl pod %s succeeded", pod.Name)
			return nil
		}
		if p.Status.Phase == corev1.PodFailed {
			t.Fatalf("%s not reachable in-cluster: curl pod %s failed", url, pod.Name)
		}
		return fmt.Errorf("curl pod %s phase: %s", pod.Name, p.Status.Phase)
	}); err != nil {
		t.Fatalf("%s not reachable in-cluster: %v", url, err)
	}
}

// certVolumesForURL returns the Pod volume, VolumeMount, and curl "--cacert"
// argument needed to verify an HTTPS url against the test CAs published in the testCAsConfigMap.
func certVolumesForURL(url string) ([]corev1.Volume, []corev1.VolumeMount, string) {
	if !strings.HasPrefix(url, "https://") {
		return nil, nil, ""
	}
	const mountPath = "/etc/test-cas"
	volumes := []corev1.Volume{{
		Name: "test-cas",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: testCAsConfigMap},
			},
		},
	}}
	mounts := []corev1.VolumeMount{{Name: "test-cas", MountPath: mountPath, ReadOnly: true}}
	cacertFlag := "--cacert " + mountPath + "/" + testCAsConfigMapKey + " "
	return volumes, mounts, cacertFlag
}

// newHTTPClient returns a HTTP client for the given tailnet client.
// When running against devcontrol, trusts Pebble testCAs. Otherwise,
// trusts Let's Encrypt staging testCA.
func newHTTPClient(cl *tsnet.Server) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: testCAs},
			DialContext:     cl.Dial,
		},
	}
}

func verifyConnectorTailnet(t *testing.T, cn *tsapi.Connector, cl *tsnet.Server) error {
	t.Helper()
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
	if err := tstest.WaitFor(3*time.Minute, func() error {
		var secrets corev1.SecretList
		if err := kubeClient.List(t.Context(), &secrets,
			client.InNamespace("tailscale"),
			client.MatchingLabels{
				"tailscale.com/parent-resource-type": "connector",
				"tailscale.com/parent-resource":      cn.Name,
			},
		); err != nil {
			return err
		}
		if len(secrets.Items) == 0 {
			return fmt.Errorf("no state secrets found for Connector %q yet", cn.Name)
		}
		fqdn := strings.TrimSuffix(string(secrets.Items[0].Data[kubetypes.KeyDeviceFQDN]), ".")
		_, tailnet, ok := strings.Cut(fqdn, ".")
		if !ok {
			return fmt.Errorf("Connector %q: device FQDN %q has no domain yet", cn.Name, fqdn)
		}
		if tailnet != expectedTailnet {
			return fmt.Errorf("Connector %q on wrong tailnet: got domain %q, want %q", cn.Name, tailnet, expectedTailnet)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("Connector %q not on expected tailnet: %v", cn.Name, err)
	}
	return nil
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

func newTailnetNode(t *testing.T, cl *tailscale.Client, hostname string) *tsnet.Server {
	t.Helper()
	caps := tailscale.KeyCapabilities{}
	caps.Devices.Create.Preauthorized = true
	caps.Devices.Create.Ephemeral = true
	caps.Devices.Create.Tags = []string{"tag:k8s"}
	authKey, err := cl.Keys().CreateAuthKey(t.Context(), tailscale.CreateKeyRequest{Capabilities: caps})
	if err != nil {
		t.Fatalf("creating auth key: %v", err)
	}
	t.Cleanup(func() { cl.Keys().Delete(context.Background(), authKey.ID) })

	srv := &tsnet.Server{
		ControlURL: cl.BaseURL.String(),
		Hostname:   hostname,
		Ephemeral:  true,
		Store:      &mem.Store{},
		AuthKey:    authKey.Key,
	}
	if _, err := srv.Up(t.Context()); err != nil {
		t.Fatalf("bringing up node: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}
