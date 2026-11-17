// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/client/tailscale/v2"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

// TestAPIServerProxyGroupAuth exercises the API server proxy deployed via a kube-apiserver ProxyGroup in
// auth mode: requests from the tailnet are impersonated using the caller's tailnet identity, so the test
// node's requests carry the ts:e2e-test-proxy group from the tailscale.com/cap/kubernetes grant in
// acl.hujson. It drives a ConfigMap through its lifecycle via the proxy, verifies the impersonated group
// cannot exceed its RBAC, then deletes the ProxyGroup and verifies everything is cleaned up.
//
// See [TestMain] for test requirements.
func TestAPIServerProxyGroupAuth(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestAPIServerProxyGroupAuth requires a working tailnet client")
	}

	t.Parallel()

	pcName := applyProxyGroupProxyClass(t)

	// Create role and role binding to allow the group we'll impersonate to manage ConfigMaps.
	roleName := generateName("api-proxy-crud")
	createAndCleanup(t, kubeClient, &rbacv1.Role{
		ObjectMeta: objectMeta(ns, roleName),
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Verbs:     []string{"get", "list", "create", "update", "delete"},
			Resources: []string{"configmaps"},
		}},
	})
	createAndCleanup(t, kubeClient, &rbacv1.RoleBinding{
		ObjectMeta: objectMeta(ns, roleName),
		Subjects: []rbacv1.Subject{{
			Kind: "Group",
			Name: "ts:e2e-test-proxy",
		}},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: roleName,
		},
	})

	// The ProxyGroup is deleted by the test itself to verify shutdown, so it is not created via
	// createAndCleanup, whose cleanup reports an error when the object is already gone. The cleanup
	// here only covers failures before the shutdown phase runs.
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("api-proxy-auth")},
		Spec: tsapi.ProxyGroupSpec{
			Type:       tsapi.ProxyGroupTypeKubernetesAPIServer,
			ProxyClass: pcName,
			KubeAPIServer: &tsapi.KubeAPIServerConfig{
				Mode: new(tsapi.APIServerProxyModeAuth),
			},
		},
	}

	if err := kubeClient.Create(t.Context(), pg); err != nil {
		t.Fatalf("creating ProxyGroup %s: %v", pg.Name, err)
	}

	t.Cleanup(func() {
		if err := client.IgnoreNotFound(kubeClient.Delete(context.Background(), pg)); err != nil {
			t.Errorf("error cleaning up ProxyGroup %s: %v", pg.Name, err)
		}
	})

	proxyURL := waitForKubeAPIServerProxyReady(t, pg.Name)

	proxyCl, err := client.New(&rest.Config{Host: proxyURL}, client.Options{
		HTTPClient: newHTTPClient(tnClient),
	})
	if err != nil {
		t.Fatalf("creating client for %s: %v", proxyURL, err)
	}

	runAPIServerProxyCRUD(t, proxyCl)

	// The impersonated group has no access to Secrets, so the request must be rejected by RBAC. This
	// proves the caller's tailnet identity, not the proxy's own ServiceAccount, is what gets authorized.
	// Note the tailscale namespace is not used here: TestProxy grants this group secret access there
	// and runs in parallel.
	forbiddenSecret := corev1.Secret{ObjectMeta: objectMeta(ns, "does-not-exist")}
	if err = get(t.Context(), proxyCl, &forbiddenSecret); !apierrors.IsForbidden(err) {
		t.Fatalf("expected forbidden error fetching Secret via proxy, got: %v", err)
	}

	// Shutdown: deleting the ProxyGroup must remove the StatefulSet and the Tailscale Service.
	if err = kubeClient.Delete(t.Context(), pg); err != nil {
		t.Fatalf("deleting ProxyGroup %s: %v", pg.Name, err)
	}

	waitForKubeAPIServerProxyShutdown(t, pg.Name)
}

// TestAPIServerProxyGroupNoAuth exercises the API server proxy deployed via a kube-apiserver ProxyGroup
// in noauth mode: the proxy passes the client's own Authorization header through untouched, so the test
// authenticates with a ServiceAccount token minted via the TokenRequest API and the API server authorizes
// the ServiceAccount's own RBAC.
//
// See [TestMain] for test requirements.
func TestAPIServerProxyGroupNoAuth(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestAPIServerProxyGroupNoAuth requires a working tailnet client")
	}
	t.Parallel()

	pcName := applyProxyGroupProxyClass(t)

	// Create a ServiceAccount allowed to manage ConfigMaps, and mint a token for it.
	saName := generateName("api-proxy-noauth")
	createAndCleanup(t, kubeClient, &corev1.ServiceAccount{
		ObjectMeta: objectMeta(ns, saName),
	})

	createAndCleanup(t, kubeClient, &rbacv1.Role{
		ObjectMeta: objectMeta(ns, saName),
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Verbs:     []string{"get", "list", "create", "update", "delete"},
			Resources: []string{"configmaps"},
		}},
	})

	createAndCleanup(t, kubeClient, &rbacv1.RoleBinding{
		ObjectMeta: objectMeta(ns, saName),
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      saName,
			Namespace: ns,
		}},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: saName,
		},
	})

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		t.Fatalf("creating clientset: %v", err)
	}

	tok, err := clientset.CoreV1().ServiceAccounts(ns).CreateToken(t.Context(), saName, &authenticationv1.TokenRequest{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("minting token for ServiceAccount %s: %v", saName, err)
	}

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("api-proxy-noauth")},
		Spec: tsapi.ProxyGroupSpec{
			Type:       tsapi.ProxyGroupTypeKubernetesAPIServer,
			ProxyClass: pcName,
			KubeAPIServer: &tsapi.KubeAPIServerConfig{
				Mode: new(tsapi.APIServerProxyModeNoAuth),
			},
		},
	}

	createAndCleanup(t, kubeClient, pg)

	proxyURL := waitForKubeAPIServerProxyReady(t, pg.Name)

	// controller-runtime uses a provided HTTP client as-is, without applying rest.Config's transport
	// wrappers, so the bearer token must be attached to the transport directly.
	httpCl := newHTTPClient(tnClient)
	httpCl.Transport = transport.NewBearerAuthRoundTripper(tok.Status.Token, httpCl.Transport)
	proxyCl, err := client.New(&rest.Config{Host: proxyURL}, client.Options{
		HTTPClient: httpCl,
	})
	if err != nil {
		t.Fatalf("creating client for %s: %v", proxyURL, err)
	}

	runAPIServerProxyCRUD(t, proxyCl)

	// The ServiceAccount has no access to Secrets, so the request must be rejected by RBAC. This proves
	// the passed-through token, not the proxy's own identity, is what gets authorized.
	forbiddenSecret := corev1.Secret{ObjectMeta: objectMeta(ns, "does-not-exist")}
	if err = get(t.Context(), proxyCl, &forbiddenSecret); !apierrors.IsForbidden(err) {
		t.Fatalf("expected forbidden error fetching Secret via proxy, got: %v", err)
	}
}

// applyProxyGroupProxyClass creates a ProxyClass for kube-apiserver ProxyGroups to use and returns its
// name. The suite's default ProxyClass configures a Tailscale init container, which ProxyGroups of type
// kube-apiserver reject, and the operator applies the default class to any ProxyGroup that does not name
// its own, so every kube-apiserver ProxyGroup in these tests must reference a class like this one.
func applyProxyGroupProxyClass(t *testing.T) string {
	t.Helper()

	var env []tsapi.Env
	if *fDevcontrol {
		env = []tsapi.Env{
			{
				Name:  "TS_DEBUG_ACME_DIRECTORY_URL",
				Value: "https://pebble:14000/dir",
			},
		}
	}

	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("api-proxy")},
		Spec: tsapi.ProxyClassSpec{
			UseLetsEncryptStagingEnvironment: !*fDevcontrol,
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleContainer: &tsapi.Container{
						ImagePullPolicy: "IfNotPresent",
						Env:             env,
					},
				},
			},
		},
	}

	createAndCleanup(t, kubeClient, pc)
	if err := tstest.WaitFor(time.Minute, func() error {
		if err := get(t.Context(), kubeClient, pc); err != nil {
			return err
		}

		if !tsoperator.ProxyClassIsReady(pc) {
			return fmt.Errorf("ProxyClass %s not ready yet", pc.Name)
		}

		return nil
	}); err != nil {
		t.Fatalf("waiting for ProxyClass %s to be ready: %v", pc.Name, err)
	}

	return pc.Name
}

// waitForKubeAPIServerProxyReady waits for the ProxyGroup to be ready with the URL of its Tailscale
// Service published in the status, and returns that URL. Readiness covers the whole chain: pods running,
// TLS cert issued, and the Tailscale Service advertised by the replicas.
func waitForKubeAPIServerProxyReady(t *testing.T, pgName string) string {
	t.Helper()

	pg := &tsapi.ProxyGroup{ObjectMeta: metav1.ObjectMeta{Name: pgName}}
	trigger := triggerReconcile(t, client.ObjectKey{Name: pgName}, &tsapi.ProxyGroup{}, 30*time.Second)

	if err := tstest.WaitFor(5*time.Minute, func() error {
		trigger()
		if err := get(t.Context(), kubeClient, pg); err != nil {
			return err
		}

		if !tsoperator.ProxyGroupIsReady(pg) {
			ready := meta.FindStatusCondition(pg.Status.Conditions, string(tsapi.ProxyGroupReady))
			if ready == nil {
				return fmt.Errorf("ProxyGroup %s has no %s condition yet", pgName, tsapi.ProxyGroupReady)
			}

			return fmt.Errorf("ProxyGroup %s not ready: reason=%s message=%q", pgName, ready.Reason, ready.Message)
		}

		if pg.Status.URL == "" {
			return fmt.Errorf("ProxyGroup %s is ready but status.url is not set yet", pgName)
		}

		return nil
	}); err != nil {
		t.Fatalf("waiting for ProxyGroup %s to be ready: %v", pgName, err)
	}

	return pg.Status.URL
}

// waitForKubeAPIServerProxyShutdown waits for a deleted kube-apiserver ProxyGroup's resources to be
// cleaned up: the ProxyGroup itself (its finalizer released), its StatefulSet, and its Tailscale Service.
func waitForKubeAPIServerProxyShutdown(t *testing.T, pgName string) {
	t.Helper()

	if err := tstest.WaitFor(2*time.Minute, func() error {
		pg := &tsapi.ProxyGroup{ObjectMeta: metav1.ObjectMeta{Name: pgName}}
		if err := get(t.Context(), kubeClient, pg); !apierrors.IsNotFound(err) {
			return fmt.Errorf("ProxyGroup %s still exists (err=%v)", pgName, err)
		}

		sts := &appsv1.StatefulSet{ObjectMeta: objectMeta("tailscale", pgName)}
		if err := get(t.Context(), kubeClient, sts); !apierrors.IsNotFound(err) {
			return fmt.Errorf("StatefulSet %s still exists (err=%v)", pgName, err)
		}

		if _, err := tsClient.VIPServices().Get(t.Context(), "svc:"+pgName); !tailscale.IsNotFound(err) {
			return fmt.Errorf("Tailscale Service svc:%s still exists (err=%v)", pgName, err)
		}

		return nil
	}); err != nil {
		t.Fatalf("waiting for ProxyGroup %s to shut down: %v", pgName, err)
	}
}

// runAPIServerProxyCRUD drives a ConfigMap through its lifecycle via the given proxy client, verifying
// the effect of every step against the cluster directly via kubeClient.
func runAPIServerProxyCRUD(t *testing.T, proxyCl client.Client) {
	t.Helper()

	name := generateName("api-proxy-crud")
	cm := &corev1.ConfigMap{
		ObjectMeta: objectMeta(ns, name),
		Data:       map[string]string{"phase": "created"},
	}

	// The first request may race the test node learning about the freshly advertised Tailscale Service,
	// so retry for a while.
	if err := tstest.WaitFor(2*time.Minute, func() error {
		err := proxyCl.Create(t.Context(), cm)
		switch {
		case apierrors.IsAlreadyExists(err):
			return nil
		case err != nil:
			t.Logf("create ConfigMap via proxy: %v", err)
		}

		return err
	}); err != nil {
		t.Fatalf("creating ConfigMap %s via proxy: %v", name, err)
	}

	t.Cleanup(func() {
		if err := client.IgnoreNotFound(kubeClient.Delete(context.Background(), cm)); err != nil {
			t.Errorf("error cleaning up ConfigMap %s: %v", name, err)
		}
	})

	got := &corev1.ConfigMap{ObjectMeta: objectMeta(ns, name)}
	if err := get(t.Context(), kubeClient, got); err != nil {
		t.Fatalf("ConfigMap %s created via proxy is not visible directly: %v", name, err)
	}

	if got.Data["phase"] != "created" {
		t.Fatalf("ConfigMap %s: phase = %q, want %q", name, got.Data["phase"], "created")
	}

	got.Data["phase"] = "updated"
	if err := proxyCl.Update(t.Context(), got); err != nil {
		t.Fatalf("updating ConfigMap %s via proxy: %v", name, err)
	}

	if err := get(t.Context(), kubeClient, got); err != nil {
		t.Fatalf("getting ConfigMap %s directly after update: %v", name, err)
	}

	if got.Data["phase"] != "updated" {
		t.Fatalf("ConfigMap %s: phase = %q, want %q", name, got.Data["phase"], "updated")
	}

	var cms corev1.ConfigMapList
	if err := proxyCl.List(t.Context(), &cms, client.InNamespace(ns)); err != nil {
		t.Fatalf("listing ConfigMaps via proxy: %v", err)
	}

	if !slices.ContainsFunc(cms.Items, func(c corev1.ConfigMap) bool { return c.Name == name }) {
		t.Fatalf("ConfigMap %s missing from list of %d ConfigMaps via proxy", name, len(cms.Items))
	}

	if err := proxyCl.Delete(t.Context(), cm); err != nil {
		t.Fatalf("deleting ConfigMap %s via proxy: %v", name, err)
	}

	if err := get(t.Context(), kubeClient, &corev1.ConfigMap{ObjectMeta: objectMeta(ns, name)}); !apierrors.IsNotFound(err) {
		t.Fatalf("ConfigMap %s deleted via proxy still exists (err=%v)", name, err)
	}
}
