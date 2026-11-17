// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/client/tailscale/v2"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

// See [TestMain] for test requirements. Additionally, the cluster's Nodes must
// have ExternalIP addresses, so this test skips on kind clusters.
func TestProxyGroupStaticEndpoints(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestProxyGroupStaticEndpoints requires a working tailnet client")
	}
	externalIPs := requireNodeExternalIPs(t)

	t.Parallel()

	// The port ranges of ProxyClasses must not clash, so each static
	// endpoints test uses its own range.
	ports := tsapi.PortRange{Port: 32759, EndPort: 32767}
	pc := applyStaticEndpointsProxyClass(t, ports)

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("static-endpoints"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:       tsapi.ProxyGroupTypeEgress,
			ProxyClass: pc.Name,
			Replicas:   new(int32(2)),
		},
	}
	createAndCleanup(t, kubeClient, pg)

	devices := waitForProxyGroupDevices(t, pg.Name, 2, true)
	verifyStaticEndpoints(t, "proxygroup", pg.Name, 2, ports, externalIPs, devices)

	// Removing static endpoints from the ProxyClass must delete the NodePort
	// Services and stop advertising static endpoints.
	removeStaticEndpoints(t, pc.Name)
	waitForNodePortServices(t, "proxygroup", pg.Name, 0)
	waitForProxyGroupDevices(t, pg.Name, 2, false)
	waitForNoPortEnv(t, "proxygroup", pg.Name)
}

// TestProxyGroupForegroundDelete checks that a ProxyGroup deleted with a
// Foreground cascade finishes its cleanup: the ProxyGroup goes away, its
// devices are deleted from the tailnet, and its state Secrets are deleted. A
// Foreground delete makes the garbage collector remove owned objects before
// the owner, so the state Secrets must not be owned by the ProxyGroup.
//
// See [TestMain] for test requirements.
func TestProxyGroupForegroundDelete(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestProxyGroupForegroundDelete requires a working tailnet client")
	}
	t.Parallel()

	t.Run("egress", func(t *testing.T) {
		t.Parallel()

		pg := &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{Name: generateName("fg-delete-egress")},
			Spec: tsapi.ProxyGroupSpec{
				Type:     tsapi.ProxyGroupTypeEgress,
				Replicas: new(int32(2)),
			},
		}
		createAndCleanup(t, kubeClient, pg)
		waitForProxyGroupDevices(t, pg.Name, 2, false)

		foregroundDeleteProxyGroup(t, pg)
	})

	t.Run("kube-apiserver", func(t *testing.T) {
		t.Parallel()

		pg := &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{Name: generateName("fg-delete-api")},
			Spec: tsapi.ProxyGroupSpec{
				Type:       tsapi.ProxyGroupTypeKubernetesAPIServer,
				ProxyClass: applyProxyGroupProxyClass(t),
				Replicas:   new(int32(2)),
				KubeAPIServer: &tsapi.KubeAPIServerConfig{
					Mode: new(tsapi.APIServerProxyModeNoAuth),
				},
			},
		}
		createAndCleanup(t, kubeClient, pg)
		waitForKubeAPIServerProxyReady(t, pg.Name)

		foregroundDeleteProxyGroup(t, pg)
		waitForKubeAPIServerProxyShutdown(t, pg.Name)
	})
}

// foregroundDeleteProxyGroup deletes the ProxyGroup with a Foreground cascade
// and waits for it to go away. It then checks that the ProxyGroup's devices
// are deleted from the tailnet and that its state Secrets are deleted.
func foregroundDeleteProxyGroup(t *testing.T, pg *tsapi.ProxyGroup) {
	t.Helper()

	replicas := int(*pg.Spec.Replicas)

	deviceIDs := make(map[string]bool)
	for _, id := range deviceIDsByTailnetIP(t, "proxygroup", pg.Name) {
		deviceIDs[id] = true
	}
	if len(deviceIDs) != replicas {
		t.Fatalf("ProxyGroup %s has device IDs %v in its state Secrets, want %d devices", pg.Name, deviceIDs, replicas)
	}

	// Whether the garbage collector deletes owned state Secrets before the
	// operator's finalizers run depends on timing, so also check for the
	// owner reference directly.
	var secrets corev1.SecretList
	if err := kubeClient.List(t.Context(), &secrets, client.InNamespace("tailscale"), stateSecretLabels(pg.Name)); err != nil {
		t.Fatalf("listing state Secrets: %v", err)
	}
	for _, s := range secrets.Items {
		for _, ref := range s.OwnerReferences {
			if ref.UID == pg.UID {
				t.Fatalf("state Secret %s is owned by ProxyGroup %s, so a Foreground delete can remove it before the finalizers run", s.Name, pg.Name)
			}
		}
	}

	if err := kubeClient.Delete(t.Context(), pg, client.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil {
		t.Fatalf("deleting ProxyGroup %s: %v", pg.Name, err)
	}

	if err := tstest.WaitFor(3*time.Minute, func() error {
		cur := &tsapi.ProxyGroup{ObjectMeta: metav1.ObjectMeta{Name: pg.Name}}
		if err := get(t.Context(), kubeClient, cur); !apierrors.IsNotFound(err) {
			return fmt.Errorf("ProxyGroup %s still exists with finalizers %v (err=%v)", pg.Name, cur.Finalizers, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for ProxyGroup %s to be deleted: %v", pg.Name, err)
	}

	for id := range deviceIDs {
		_, err := tsClient.Devices().Get(t.Context(), id)
		switch {
		case tailscale.IsNotFound(err):
		case err != nil:
			t.Errorf("getting device %s: %v", id, err)
		default:
			t.Errorf("device %s of ProxyGroup %s is still in the tailnet", id, pg.Name)
		}
	}

	if err := kubeClient.List(t.Context(), &secrets, client.InNamespace("tailscale"), stateSecretLabels(pg.Name)); err != nil {
		t.Fatalf("listing state Secrets: %v", err)
	}
	for _, s := range secrets.Items {
		t.Errorf("state Secret %s of ProxyGroup %s still exists", s.Name, pg.Name)
	}
}

// stateSecretLabels matches the state Secrets of the ProxyGroup.
func stateSecretLabels(pgName string) client.MatchingLabels {
	return client.MatchingLabels{
		"tailscale.com/parent-resource-type": "proxygroup",
		"tailscale.com/parent-resource":      pgName,
		"tailscale.com/secret-type":          "state",
	}
}

// waitForProxyGroupDevices waits for the ProxyGroup to be ready with the given
// number of devices in its status, and for every device to report static
// endpoints if wantStaticEndpoints is true, or none if it is false.
func waitForProxyGroupDevices(t *testing.T, name string, replicas int, wantStaticEndpoints bool) []staticEndpointsDevice {
	t.Helper()

	trigger := triggerReconcile(t, client.ObjectKey{Name: name}, &tsapi.ProxyGroup{}, 30*time.Second)

	var devices []staticEndpointsDevice
	if err := tstest.WaitFor(5*time.Minute, func() error {
		trigger()
		pg := &tsapi.ProxyGroup{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if err := get(t.Context(), kubeClient, pg); err != nil {
			return err
		}
		if !tsoperator.ProxyGroupIsReady(pg) {
			return fmt.Errorf("ProxyGroup %s not ready: %v", name, pg.Status.Conditions)
		}
		devices = devices[:0]
		for _, d := range pg.Status.Devices {
			devices = append(devices, staticEndpointsDevice{tailnetIPs: d.TailnetIPs, staticEndpoints: d.StaticEndpoints})
		}
		return checkDevices("ProxyGroup", name, devices, replicas, wantStaticEndpoints)
	}); err != nil {
		t.Fatalf("waiting for ProxyGroup %s devices: %v", name, err)
	}

	return devices
}
