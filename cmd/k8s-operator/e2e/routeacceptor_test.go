// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/client/tailscale/v2"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
)

// routeAcceptorMu serializes the tests that deploy a RouteAcceptor: each one runs a tailscaled in every node's
// host network namespace, so only one can exist in a cluster at a time.
var routeAcceptorMu sync.Mutex

// A subnet in 10.0.0.0/8 so that its route is auto-approved and reachable on
// port 80 per the ACL in acl.hujson.
const (
	testSubnet   = "10.99.0.0/24"
	testSubnetIP = "10.99.0.1"
)

// TestRouteAcceptor verifies that a RouteAcceptor makes a subnet route advertised
// to the tailnet reachable from Pods, and that its devices are removed from the
// tailnet when it is deleted.
//
// See [TestMain] for test requirements.
func TestRouteAcceptor(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestRouteAcceptor requires a working tailnet client")
	}

	t.Parallel()
	routeAcceptorMu.Lock()
	defer routeAcceptorMu.Unlock()

	router := subnetRouterPod(t, generateName("subnet-router"), testSubnet, testSubnetIP)
	createAndCleanup(t, kubeClient, router)

	ra := &tsapi.RouteAcceptor{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("route-acceptor"),
		},
		Spec: tsapi.RouteAcceptorSpec{
			ProxyClass: "default",
		},
	}
	if err := kubeClient.Create(t.Context(), ra); err != nil {
		t.Fatalf("creating RouteAcceptor: %v", err)
	}
	t.Cleanup(func() {
		// The test deletes the RouteAcceptor itself on success.
		if err := kubeClient.Delete(context.Background(), ra); err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("error cleaning up RouteAcceptor %s: %v", ra.Name, err)
		}
	})

	ready := waitForRouteAcceptorRoute(t, ra.Name, testSubnet)

	// Every node runs a device.
	var nodes corev1.NodeList
	if err := kubeClient.List(t.Context(), &nodes); err != nil {
		t.Fatalf("listing nodes: %v", err)
	}
	if got, want := len(ready.Status.Nodes), len(nodes.Items); got != want {
		t.Errorf("RouteAcceptor.Status.Nodes has %d entries, want one per node (%d)", got, want)
	}
	for _, n := range ready.Status.Nodes {
		if !n.Ready || n.Hostname == "" || len(n.TailnetIPs) == 0 {
			t.Errorf("device on node %s is not ready: %+v", n.Name, n)
		}
	}

	// Pods reach the subnet through the tailnet.
	requireTargetIsReachable(t, fmt.Sprintf("http://%s/healthz", testSubnetIP))

	// Deleting the RouteAcceptor removes its devices from the tailnet.
	deviceIDs := deviceIDsForRouteAcceptor(t, ra.Name)
	if len(deviceIDs) == 0 {
		t.Fatal("no device IDs recorded in the RouteAcceptor's state Secrets")
	}
	if err := kubeClient.Delete(t.Context(), ra); err != nil {
		t.Fatalf("deleting RouteAcceptor: %v", err)
	}
	if err := tstest.WaitFor(3*time.Minute, func() error {
		err := kubeClient.Get(t.Context(), client.ObjectKey{Name: ra.Name}, &tsapi.RouteAcceptor{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("RouteAcceptor %s still exists", ra.Name)
	}); err != nil {
		t.Fatalf("waiting for RouteAcceptor deletion: %v", err)
	}
	for _, id := range deviceIDs {
		if err := tstest.WaitFor(time.Minute, func() error {
			_, err := tsClient.Devices().Get(t.Context(), id)
			if tailscale.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("device %s still exists", id)
		}); err != nil {
			t.Errorf("device %s was not removed from the tailnet: %v", id, err)
		}
	}
}

// routerOpts configures subnetRouterPod.
// subnetRouterPod returns a Pod that joins the tailnet as an ephemeral subnet
// router for subnet and answers HTTP requests on subnetIP port 80
// (containerboot's health check endpoint), so that tests can tell whether the
// subnet is reachable. The device disappears from the tailnet with the Pod.
func subnetRouterPod(t *testing.T, name, subnet, subnetIP string) *corev1.Pod {
	t.Helper()

	caps := tailscale.KeyCapabilities{}
	caps.Devices.Create.Preauthorized = true
	caps.Devices.Create.Ephemeral = true
	caps.Devices.Create.Tags = []string{"tag:k8s"}
	authKey, err := tsClient.Keys().CreateAuthKey(t.Context(), tailscale.CreateKeyRequest{Capabilities: caps})
	if err != nil {
		t.Fatalf("creating auth key: %v", err)
	}
	t.Cleanup(func() { tsClient.Keys().Delete(context.Background(), authKey.ID) })

	image := proxyImage(t)
	privileged := true
	return &corev1.Pod{
		ObjectMeta: objectMeta(ns, name),
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:            "subnet",
				Image:           image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
				Command:         []string{"/bin/sh", "-c"},
				Args:            []string{fmt.Sprintf("ip addr add %s/32 dev lo", subnetIP)},
			}},
			Containers: []corev1.Container{{
				Name:            "tailscale",
				Image:           image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
				Env: []corev1.EnvVar{
					{Name: "TS_AUTHKEY", Value: authKey.Key},
					{Name: "TS_HOSTNAME", Value: name},
					{Name: "TS_ROUTES", Value: subnet},
					{Name: "TS_USERSPACE", Value: "false"},
					// Keep state on disk: the Pod's ServiceAccount cannot
					// write Secrets.
					{Name: "TS_KUBE_SECRET", Value: ""},
					{Name: "TS_STATE_DIR", Value: "/tmp"},
					{Name: "TS_ENABLE_HEALTH_CHECK", Value: "true"},
					{Name: "TS_LOCAL_ADDR_PORT", Value: "[::]:80"},
				},
			}},
		},
	}
}

// proxyImage returns the image the operator uses for its proxies, from the
// operator Deployment's PROXY_IMAGE env var.
func proxyImage(t *testing.T) string {
	t.Helper()
	var deploy appsv1.Deployment
	if err := kubeClient.Get(t.Context(), client.ObjectKey{Namespace: "tailscale", Name: "operator"}, &deploy); err != nil {
		t.Fatalf("getting operator Deployment: %v", err)
	}
	for _, c := range deploy.Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			if e.Name == "PROXY_IMAGE" && e.Value != "" {
				return e.Value
			}
		}
	}
	t.Fatal("operator Deployment does not set PROXY_IMAGE")
	return ""
}

// waitForRouteAcceptorCondition waits for the RouteAcceptor to have the given
// condition with the given status and reason.
func waitForRouteAcceptorCondition(t *testing.T, name string, typ tsapi.ConditionType, status metav1.ConditionStatus, reason string) {
	t.Helper()
	if err := tstest.WaitFor(3*time.Minute, func() error {
		var ra tsapi.RouteAcceptor
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, &ra); err != nil {
			return err
		}
		for _, c := range ra.Status.Conditions {
			if c.Type != string(typ) {
				continue
			}
			if c.Status == status && c.Reason == reason {
				return nil
			}
			return fmt.Errorf("RouteAcceptor %s: %s is %s/%s (%s), want %s/%s", name, typ, c.Status, c.Reason, c.Message, status, reason)
		}
		return fmt.Errorf("RouteAcceptor %s has no %s condition yet", name, typ)
	}); err != nil {
		t.Fatal(err)
	}
}

// waitForRouteAcceptorRoute waits for the RouteAcceptor to be ready and to
// accept the given route on every node, and returns it.
func waitForRouteAcceptorRoute(t *testing.T, name, route string) *tsapi.RouteAcceptor {
	t.Helper()
	forceReconcile := triggerReconcile(t,
		client.ObjectKey{Name: name}, &tsapi.RouteAcceptor{}, 30*time.Second)

	ra := &tsapi.RouteAcceptor{}
	if err := tstest.WaitFor(5*time.Minute, func() error {
		forceReconcile()
		ra = &tsapi.RouteAcceptor{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, ra); err != nil {
			return err
		}
		for _, c := range ra.Status.Conditions {
			if c.Type != string(tsapi.RouteAcceptorReady) {
				continue
			}
			if c.Status != metav1.ConditionTrue {
				return fmt.Errorf("RouteAcceptor %s not ready: %s: %s", name, c.Reason, c.Message)
			}
		}
		if len(ra.Status.Nodes) == 0 {
			return fmt.Errorf("RouteAcceptor %s has no device info yet", name)
		}
		for _, n := range ra.Status.Nodes {
			if !n.Ready {
				return fmt.Errorf("device on node %s is not ready yet", n.Name)
			}
			if !slices.Contains(n.AcceptedRoutes, route) {
				return fmt.Errorf("device on node %s does not accept %s yet, accepted routes: %v", n.Name, route, n.AcceptedRoutes)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for RouteAcceptor %s to accept %s: %v", name, route, err)
	}
	return ra
}

// deviceIDsForRouteAcceptor returns the device IDs recorded in the
// RouteAcceptor's state Secrets.
func deviceIDsForRouteAcceptor(t *testing.T, name string) []string {
	t.Helper()
	var secrets corev1.SecretList
	if err := kubeClient.List(t.Context(), &secrets,
		client.InNamespace("tailscale"),
		client.MatchingLabels{
			kubetypes.LabelSecretType:            kubetypes.LabelSecretTypeState,
			"tailscale.com/parent-resource-type": "routeacceptor",
			"tailscale.com/parent-resource":      name,
		},
	); err != nil {
		t.Fatalf("listing state Secrets for RouteAcceptor %s: %v", name, err)
	}
	var ids []string
	for _, s := range secrets.Items {
		if id := string(s.Data[kubetypes.KeyDeviceID]); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}
