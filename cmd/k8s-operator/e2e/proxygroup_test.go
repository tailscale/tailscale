// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
