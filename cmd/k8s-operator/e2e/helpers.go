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
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
)

func generateName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, strings.ToLower(rand.Text()))
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
