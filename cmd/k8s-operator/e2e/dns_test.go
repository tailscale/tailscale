// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tsnet"
)

const tsNetStubZone = `
ts.net:53 {
    errors
    cache 30
    forward . %s
}
`

// See [TestMain] for test requirements.
func TestDNS(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestDNS requires a working tailnet client")
	}
	t.Parallel()

	nameserverIP, err := nameserverClusterIP(t.Context())
	if err != nil {
		t.Fatalf("getting nameserver Service IP: %v", err)
	}
	if !patchClusterDNS(t, nameserverIP) {
		t.Skip("cluster DNS is not a patchable CoreDNS/kube-dns (e.g. Cloud DNS); cannot forward ts.net in-cluster")
	}

	tests := []struct {
		name    string
		client  *tsnet.Server
		target  tailnetTarget
		tailnet string
	}{
		{
			name:   "first-tailnet",
			client: tnClient,
			target: tnTarget,
		},
		{
			name:    "second-tailnet",
			client:  secondTNClient,
			target:  secondTNTarget,
			tailnet: "second-tailnet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.client == nil {
				t.Skipf("%s not configured", tt.name)
			}

			pg := &tsapi.ProxyGroup{
				ObjectMeta: metav1.ObjectMeta{Name: generateName("test-dns-egress")},
				Spec: tsapi.ProxyGroupSpec{
					Type:    tsapi.ProxyGroupTypeEgress,
					Tailnet: tt.tailnet,
				},
			}
			createAndCleanup(t, kubeClient, pg)
			if err := verifyProxyGroupTailnet(t, pg, tt.client); err != nil {
				t.Fatalf("verifying ProxyGroup %s is registered to the expected tailnet: %v", pg.Name, err)
			}

			svc := egressService(generateName("test-dns-egress"), map[string]string{
				"tailscale.com/tailnet-fqdn": tt.target.fqdn,
				"tailscale.com/proxy-group":  pg.Name,
			})
			createAndCleanup(t, kubeClient, svc)
			waitForEgress(t, svc.Name, pgEgressReady)
			testEgressIsReachable(t, fmt.Sprintf("http://%s:%d", tt.target.fqdn, egressPort))
		})
	}
}

func nameserverClusterIP(ctx context.Context) (string, error) {
	svc := &corev1.Service{ObjectMeta: objectMeta("tailscale", "nameserver")}
	if err := get(ctx, kubeClient, svc); err != nil {
		return "", err
	}
	if ip := svc.Spec.ClusterIP; ip != "" && ip != "None" {
		return ip, nil
	}
	return "", fmt.Errorf("nameserver Service has no ClusterIP")
}

func patchClusterDNS(t *testing.T, nameserverIP string) bool {
	t.Helper()
	coredns := &corev1.ConfigMap{ObjectMeta: objectMeta("kube-system", "coredns")}
	if err := get(t.Context(), kubeClient, coredns); err == nil && coredns.Data["Corefile"] != "" {
		patchCoreDNS(t, nameserverIP)
		return true
	}
	kubedns := &corev1.ConfigMap{ObjectMeta: objectMeta("kube-system", "kube-dns")}
	if err := get(t.Context(), kubeClient, kubedns); err == nil {
		patchKubeDNS(t, nameserverIP)
		return true
	}
	return false
}

func patchCoreDNS(t *testing.T, nameserverIP string) {
	t.Helper()
	cm := &corev1.ConfigMap{ObjectMeta: objectMeta("kube-system", "coredns")}
	if err := get(t.Context(), kubeClient, cm); err != nil {
		t.Fatalf("getting coredns ConfigMap: %v", err)
	}
	orig := cm.Data["Corefile"]
	// Strip any pre-existing ts.net block, then update.
	cm.Data["Corefile"] = stripTSNetZone(orig) + fmt.Sprintf(tsNetStubZone, nameserverIP)
	if err := kubeClient.Update(t.Context(), cm); err != nil {
		t.Fatalf("updating coredns Corefile: %v", err)
	}
	t.Log("patched CoreDNS Corefile with ts.net stub zone")

	t.Cleanup(func() {
		restore := &corev1.ConfigMap{ObjectMeta: objectMeta("kube-system", "coredns")}
		if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(restore), restore); err != nil {
			t.Errorf("restoring coredns Corefile: get: %v", err)
			return
		}
		restore.Data["Corefile"] = orig
		if err := kubeClient.Update(context.Background(), restore); err != nil {
			t.Errorf("restoring coredns Corefile: update: %v", err)
		}
	})
}

func patchKubeDNS(t *testing.T, nameserverIP string) {
	t.Helper()
	cm := &corev1.ConfigMap{ObjectMeta: objectMeta("kube-system", "kube-dns")}
	if err := get(t.Context(), kubeClient, cm); err != nil {
		t.Fatalf("getting kube-dns ConfigMap: %v", err)
	}
	origStub, hadStub := cm.Data["stubDomains"]
	stub, err := json.Marshal(map[string][]string{"ts.net": {nameserverIP}})
	if err != nil {
		t.Fatalf("marshalling stubDomains: %v", err)
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data["stubDomains"] = string(stub)
	if err := kubeClient.Update(t.Context(), cm); err != nil {
		t.Fatalf("updating kube-dns stubDomains: %v", err)
	}
	t.Log("patched kube-dns stubDomains with ts.net entry")

	t.Cleanup(func() {
		restore := &corev1.ConfigMap{ObjectMeta: objectMeta("kube-system", "kube-dns")}
		if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(restore), restore); err != nil {
			t.Errorf("restoring kube-dns stubDomains: get: %v", err)
			return
		}
		if hadStub {
			restore.Data["stubDomains"] = origStub
		} else {
			delete(restore.Data, "stubDomains")
		}
		if err := kubeClient.Update(context.Background(), restore); err != nil {
			t.Errorf("restoring kube-dns stubDomains: update: %v", err)
		}
	})
}

// stripTSNetZone removes a previously-appended `ts.net:53 { ... }` server block
// from a Corefile.
func stripTSNetZone(corefile string) string {
	idx := strings.Index(corefile, "ts.net:53 {")
	if idx == -1 {
		return corefile
	}
	rest := corefile[idx:]
	end := strings.Index(rest, "\n}")
	if end == -1 {
		return corefile[:idx]
	}
	return corefile[:idx] + rest[end+len("\n}"):]
}
