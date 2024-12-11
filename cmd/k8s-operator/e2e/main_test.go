// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/zapr"
	"github.com/tailscale/hujson"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2/clientcredentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"tailscale.com/client/tailscale"
)

const (
	e2eManagedComment = "// This is managed by the k8s-operator e2e tests"
)

var (
	tsClient   *tailscale.Client
	testGrants = map[string]string{
		"test-proxy": `{
			"src": ["tag:e2e-test-proxy"],
			"dst": ["tag:k8s-operator"],
			"app": {
				"tailscale.com/cap/kubernetes": [{
					"impersonate": {
						"groups": ["ts:e2e-test-proxy"],
					},
				}],
			},
		}`,
	}
)

// This test suite is currently not run in CI.
// It requires some setup not handled by this code:
// - Kubernetes cluster with tailscale operator installed
// - Current kubeconfig context set to connect to that cluster (directly, no operator proxy)
// - Operator installed with --set apiServerProxyConfig.mode="true"
// - ACLs that define tag:e2e-test-proxy tag. TODO(tomhjp): Can maybe replace this prereq onwards with an API key
// - OAuth client ID and secret in TS_API_CLIENT_ID and TS_API_CLIENT_SECRET env
// - OAuth client must have auth_keys and policy_file write for tag:e2e-test-proxy tag
func TestMain(m *testing.M) {
	code, err := runTests(m)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(code)
}

func runTests(m *testing.M) (int, error) {
	zlog := kzap.NewRaw([]kzap.Opts{kzap.UseDevMode(true), kzap.Level(zapcore.DebugLevel)}...).Sugar()
	logf.SetLogger(zapr.NewLogger(zlog.Desugar()))
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	if clientID := os.Getenv("TS_API_CLIENT_ID"); clientID != "" {
		cleanup, err := setupClientAndACLs()
		if err != nil {
			return 0, err
		}
		defer func() {
			err = errors.Join(err, cleanup())
		}()
	}

	return m.Run(), nil
}

func setupClientAndACLs() (cleanup func() error, _ error) {
	ctx := context.Background()
	credentials := clientcredentials.Config{
		ClientID:     os.Getenv("TS_API_CLIENT_ID"),
		ClientSecret: os.Getenv("TS_API_CLIENT_SECRET"),
		TokenURL:     "https://login.tailscale.com/api/v2/oauth/token",
		Scopes:       []string{"auth_keys", "policy_file"},
	}
	tsClient = tailscale.NewClient("-", nil)
	tsClient.HTTPClient = credentials.Client(ctx)

	if err := patchACLs(ctx, tsClient, func(acls *hujson.Value) {
		for test, grant := range testGrants {
			deleteTestGrants(test, acls)
			addTestGrant(test, grant, acls)
		}
	}); err != nil {
		return nil, err
	}

	return func() error {
		return patchACLs(ctx, tsClient, func(acls *hujson.Value) {
			for test := range testGrants {
				deleteTestGrants(test, acls)
			}
		})
	}, nil
}

func patchACLs(ctx context.Context, tsClient *tailscale.Client, patchFn func(*hujson.Value)) error {
	acls, err := tsClient.ACLHuJSON(ctx)
	if err != nil {
		return err
	}
	hj, err := hujson.Parse([]byte(acls.ACL))
	if err != nil {
		return err
	}

	patchFn(&hj)

	hj.Format()
	acls.ACL = hj.String()
	if _, err := tsClient.SetACLHuJSON(ctx, *acls, true); err != nil {
		return err
	}

	return nil
}

func addTestGrant(test, grant string, acls *hujson.Value) error {
	v, err := hujson.Parse([]byte(grant))
	if err != nil {
		return err
	}

	// Add the managed comment to the first line of the grant object contents.
	v.Value.(*hujson.Object).Members[0].Name.BeforeExtra = hujson.Extra(fmt.Sprintf("%s: %s\n", e2eManagedComment, test))

	if err := acls.Patch([]byte(fmt.Sprintf(`[{"op": "add", "path": "/grants/-", "value": %s}]`, v.String()))); err != nil {
		return err
	}

	return nil
}

func deleteTestGrants(test string, acls *hujson.Value) error {
	grants := acls.Find("/grants")

	var patches []string
	for i, g := range grants.Value.(*hujson.Array).Elements {
		members := g.Value.(*hujson.Object).Members
		if len(members) == 0 {
			continue
		}
		comment := strings.TrimSpace(string(members[0].Name.BeforeExtra))
		if name, found := strings.CutPrefix(comment, e2eManagedComment+": "); found && name == test {
			patches = append(patches, fmt.Sprintf(`{"op": "remove", "path": "/grants/%d"}`, i))
		}
	}

	// Remove in reverse order so we don't affect the found indices as we mutate.
	slices.Reverse(patches)

	if err := acls.Patch([]byte(fmt.Sprintf("[%s]", strings.Join(patches, ",")))); err != nil {
		return err
	}

	return nil
}

func objectMeta(namespace, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Namespace: namespace,
		Name:      name,
	}
}

func createAndCleanup(t *testing.T, ctx context.Context, cl client.Client, obj client.Object) {
	t.Helper()
	if err := cl.Create(ctx, obj); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cl.Delete(ctx, obj); err != nil {
			t.Errorf("error cleaning up %s %s/%s: %s", obj.GetObjectKind().GroupVersionKind(), obj.GetNamespace(), obj.GetName(), err)
		}
	})
}

func get(ctx context.Context, cl client.Client, obj client.Object) error {
	return cl.Get(ctx, client.ObjectKeyFromObject(obj), obj)
}
