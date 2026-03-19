// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/ipn"
	"tailscale.com/tstest"
)

// See [TestMain] for test requirements.
func TestProxy(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestProxy requires a working tailnet client")
	}

	// Create role and role binding to allow a group we'll impersonate to do stuff.
	createAndCleanup(t, kubeClient, &rbacv1.Role{
		ObjectMeta: objectMeta("tailscale", "read-secrets"),
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Verbs:     []string{"get"},
			Resources: []string{"secrets"},
		}},
	})
	createAndCleanup(t, kubeClient, &rbacv1.RoleBinding{
		ObjectMeta: objectMeta("tailscale", "read-secrets"),
		Subjects: []rbacv1.Subject{{
			Kind: "Group",
			Name: "ts:e2e-test-proxy",
		}},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: "read-secrets",
		},
	})

	// Get operator host name from kube secret.
	operatorSecret := corev1.Secret{
		ObjectMeta: objectMeta("tailscale", "operator"),
	}
	if err := get(t.Context(), kubeClient, &operatorSecret); err != nil {
		t.Fatal(err)
	}

	// Join tailnet as a client of the API server proxy.
	proxyCfg := &rest.Config{
		Host: fmt.Sprintf("https://%s:443", hostNameFromOperatorSecret(t, operatorSecret)),
	}
	proxyCl, err := client.New(proxyCfg, client.Options{
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: testCAs,
				},
				DialContext: tnClient.Dial,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Expect success.
	allowedSecret := corev1.Secret{
		ObjectMeta: objectMeta("tailscale", "operator"),
	}
	// Wait for up to a minute the first time we use the proxy, to give it time
	// to provision the TLS certs.
	if err := tstest.WaitFor(time.Minute, func() error {
		err := get(t.Context(), proxyCl, &allowedSecret)
		t.Logf("get Secret via proxy: %v", err)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Expect forbidden.
	forbiddenSecret := corev1.Secret{
		ObjectMeta: objectMeta("default", "operator"),
	}
	if err := get(t.Context(), proxyCl, &forbiddenSecret); err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("expected forbidden error fetching secret from default namespace: %s", err)
	}
}

func hostNameFromOperatorSecret(t *testing.T, s corev1.Secret) string {
	t.Helper()
	prefsBytes, ok := s.Data[string(s.Data["_current-profile"])]
	if !ok {
		t.Fatalf("no state in operator Secret data: %#v", s.Data)
	}

	prefs := ipn.Prefs{}
	if err := json.Unmarshal(prefsBytes, &prefs); err != nil {
		t.Fatal(err)
	}

	if prefs.Persist == nil {
		t.Fatalf("no hostname in operator Secret data: %#v", s.Data)
	}
	return prefs.Persist.UserProfile.LoginName
}
