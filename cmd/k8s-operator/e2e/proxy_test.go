// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"tailscale.com/client/tailscale"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
)

// See [TestMain] for test requirements.
func TestProxy(t *testing.T) {
	if tsClient == nil {
		t.Skip("TestProxy requires credentials for a tailscale client")
	}

	ctx := context.Background()
	cfg := config.GetConfigOrDie()
	cl, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Create role and role binding to allow a group we'll impersonate to do stuff.
	createAndCleanup(t, ctx, cl, &rbacv1.Role{
		ObjectMeta: objectMeta("tailscale", "read-secrets"),
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Verbs:     []string{"get"},
			Resources: []string{"secrets"},
		}},
	})
	createAndCleanup(t, ctx, cl, &rbacv1.RoleBinding{
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
	if err := get(ctx, cl, &operatorSecret); err != nil {
		t.Fatal(err)
	}

	// Connect to tailnet with test-specific tag so we can use the
	// [testGrants] ACLs when connecting to the API server proxy
	ts := tsnetServerWithTag(t, ctx, "tag:e2e-test-proxy")
	proxyCfg := &rest.Config{
		Host: fmt.Sprintf("https://%s:443", hostNameFromOperatorSecret(t, operatorSecret)),
		Dial: ts.Dial,
	}
	proxyCl, err := client.New(proxyCfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Expect success.
	allowedSecret := corev1.Secret{
		ObjectMeta: objectMeta("tailscale", "operator"),
	}
	// Wait for up to a minute the first time we use the proxy, to give it time
	// to provision the TLS certs.
	if err := tstest.WaitFor(time.Second*60, func() error {
		return get(ctx, proxyCl, &allowedSecret)
	}); err != nil {
		t.Fatal(err)
	}

	// Expect forbidden.
	forbiddenSecret := corev1.Secret{
		ObjectMeta: objectMeta("default", "operator"),
	}
	if err := get(ctx, proxyCl, &forbiddenSecret); err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("expected forbidden error fetching secret from default namespace: %s", err)
	}
}

func tsnetServerWithTag(t *testing.T, ctx context.Context, tag string) *tsnet.Server {
	caps := tailscale.KeyCapabilities{
		Devices: tailscale.KeyDeviceCapabilities{
			Create: tailscale.KeyDeviceCreateCapabilities{
				Reusable:      false,
				Preauthorized: true,
				Ephemeral:     true,
				Tags:          []string{tag},
			},
		},
	}

	authKey, authKeyMeta, err := tsClient.CreateKey(ctx, caps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := tsClient.DeleteKey(ctx, authKeyMeta.ID); err != nil {
			t.Errorf("error deleting auth key: %s", err)
		}
	})

	ts := &tsnet.Server{
		Hostname:  "test-proxy",
		Ephemeral: true,
		Dir:       t.TempDir(),
		AuthKey:   authKey,
	}
	_, err = ts.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ts.Close(); err != nil {
			t.Errorf("error shutting down tsnet.Server: %s", err)
		}
	})

	return ts
}

func hostNameFromOperatorSecret(t *testing.T, s corev1.Secret) string {
	profiles := map[string]any{}
	if err := json.Unmarshal(s.Data["_profiles"], &profiles); err != nil {
		t.Fatal(err)
	}
	key, ok := strings.CutPrefix(string(s.Data["_current-profile"]), "profile-")
	if !ok {
		t.Fatal(string(s.Data["_current-profile"]))
	}
	profile, ok := profiles[key]
	if !ok {
		t.Fatal(profiles)
	}

	return ((profile.(map[string]any))["Name"]).(string)
}
