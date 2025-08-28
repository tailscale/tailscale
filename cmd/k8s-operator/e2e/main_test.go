// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

// This test suite is currently not run in CI.
// It requires some setup not handled by this code:
// - Kubernetes cluster with local kubeconfig for it (direct connection, no API server proxy)
// - Tailscale operator installed with --set apiServerProxyConfig.mode="true"
// - ACLs from acl.hujson
// - OAuth client secret in TS_API_CLIENT_SECRET env, with at least auth_keys write scope and tag:k8s tag
var (
	apiClient     *tailscale.Client // For API calls to control.
	tailnetClient *tsnet.Server     // For testing real tailnet traffic.
)

func TestMain(m *testing.M) {
	code, err := runTests(m)
	if err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runTests(m *testing.M) (int, error) {
	secret := os.Getenv("TS_API_CLIENT_SECRET")
	if secret != "" {
		secretParts := strings.Split(secret, "-")
		if len(secretParts) != 4 {
			return 0, errors.New("TS_API_CLIENT_SECRET is not valid")
		}
		ctx := context.Background()
		credentials := clientcredentials.Config{
			ClientID:     secretParts[2],
			ClientSecret: secret,
			TokenURL:     "https://login.tailscale.com/api/v2/oauth/token",
			Scopes:       []string{"auth_keys"},
		}
		apiClient = tailscale.NewClient("-", nil)
		apiClient.HTTPClient = credentials.Client(ctx)

		caps := tailscale.KeyCapabilities{
			Devices: tailscale.KeyDeviceCapabilities{
				Create: tailscale.KeyDeviceCreateCapabilities{
					Reusable:      false,
					Preauthorized: true,
					Ephemeral:     true,
					Tags:          []string{"tag:k8s"},
				},
			},
		}

		authKey, authKeyMeta, err := apiClient.CreateKeyWithExpiry(ctx, caps, 10*time.Minute)
		if err != nil {
			return 0, err
		}
		defer apiClient.DeleteKey(context.Background(), authKeyMeta.ID)

		tailnetClient = &tsnet.Server{
			Hostname:  "test-proxy",
			Ephemeral: true,
			Store:     &mem.Store{},
			AuthKey:   authKey,
		}
		_, err = tailnetClient.Up(ctx)
		if err != nil {
			return 0, err
		}
		defer tailnetClient.Close()
	}

	return m.Run(), nil
}

func objectMeta(namespace, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Namespace: namespace,
		Name:      name,
	}
}

func createAndCleanup(t *testing.T, cl client.Client, obj client.Object) {
	t.Helper()

	// Try to create the object first
	err := cl.Create(t.Context(), obj)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			if updateErr := cl.Update(t.Context(), obj); updateErr != nil {
				t.Fatal(updateErr)
			}
		} else {
			t.Fatal(err)
		}
	}

	t.Cleanup(func() {
		// Use context.Background() for cleanup, as t.Context() is cancelled
		// just before cleanup functions are called.
		if err := cl.Delete(context.Background(), obj); err != nil {
			t.Errorf("error cleaning up %s %s/%s: %s", obj.GetObjectKind().GroupVersionKind(), obj.GetNamespace(), obj.GetName(), err)
		}
	})
}

func get(ctx context.Context, cl client.Client, obj client.Object) error {
	return cl.Get(ctx, client.ObjectKeyFromObject(obj), obj)
}
