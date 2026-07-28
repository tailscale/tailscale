// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"fmt"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
)

// See [TestMain] for test requirements.
func TestConnectorExitNode(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestConnectorExitNode requires a working tailnet client")
	}

	t.Parallel()

	cn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("exit-node"),
		},
		Spec: tsapi.ConnectorSpec{
			ExitNode:   true,
			ProxyClass: "default",
		},
	}
	createAndCleanup(t, kubeClient, cn)

	ready := waitForConnectorReady(t, cn.Name)
	if !ready.Status.IsExitNode {
		t.Errorf("Connector.Status.IsExitNode = false, want true")
	}
	if ready.Status.IsAppConnector {
		t.Errorf("Connector.Status.IsAppConnector = true, want false")
	}
	if ready.Status.SubnetRoutes != "" {
		t.Errorf("Connector.Status.SubnetRoutes = %q, want empty", ready.Status.SubnetRoutes)
	}

	deviceID := deviceIDForConnector(t, cn.Name)
	if err := tstest.WaitFor(time.Minute, func() error {
		dev, err := tsClient.Devices().GetWithAllFields(t.Context(), deviceID)
		if err != nil {
			return fmt.Errorf("get device %s: %w", deviceID, err)
		}
		if !slices.Contains(dev.AdvertisedRoutes, "0.0.0.0/0") ||
			!slices.Contains(dev.AdvertisedRoutes, "::/0") {
			return fmt.Errorf("device %s does not advertise exit node routes: %v", deviceID, dev.AdvertisedRoutes)
		}
		return nil
	}); err != nil {
		t.Fatalf("verifying exit node advertisement: %v", err)
	}
}

// See [TestMain] for test requirements.
func TestConnectorAppConnector(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestConnectorAppConnector requires a working tailnet client")
	}

	t.Parallel()

	// A route in 10.0.0.0/8 so it is auto-approved by the ACL in acl.hujson.
	const route = "10.50.0.0/16"

	cn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("app-connector"),
		},
		Spec: tsapi.ConnectorSpec{
			AppConnector: &tsapi.AppConnector{
				Routes: []tsapi.Route{route},
			},
			ProxyClass: "default",
		},
	}
	createAndCleanup(t, kubeClient, cn)

	ready := waitForConnectorReady(t, cn.Name)
	if !ready.Status.IsAppConnector {
		t.Errorf("Connector.Status.IsAppConnector = false, want true")
	}
	if ready.Status.IsExitNode {
		t.Errorf("Connector.Status.IsExitNode = true, want false")
	}

	deviceID := deviceIDForConnector(t, cn.Name)
	if err := tstest.WaitFor(time.Minute, func() error {
		routes, err := tsClient.Devices().SubnetRoutes(t.Context(), deviceID)
		if err != nil {
			return fmt.Errorf("get subnet routes for %s: %w", deviceID, err)
		}
		if !slices.Contains(routes.Advertised, route) {
			return fmt.Errorf("device %s does not advertise %s: %v", deviceID, route, routes.Advertised)
		}
		return nil
	}); err != nil {
		t.Fatalf("verifying app connector routes: %v", err)
	}
}

// See [TestMain] for test requirements.
func TestConnectorSubnetRouter(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestConnectorSubnetRouter requires a working tailnet client")
	}

	t.Parallel()

	// A route in 10.0.0.0/8 so it is auto-approved by the ACL in acl.hujson.
	const route = "10.40.0.0/14"

	cn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("subnet-router"),
		},
		Spec: tsapi.ConnectorSpec{
			SubnetRouter: &tsapi.SubnetRouter{
				AdvertiseRoutes: []tsapi.Route{route},
			},
			ProxyClass: "default",
		},
	}
	createAndCleanup(t, kubeClient, cn)

	ready := waitForConnectorReady(t, cn.Name)
	if ready.Status.SubnetRoutes != route {
		t.Errorf("Connector.Status.SubnetRoutes = %q, want %q", ready.Status.SubnetRoutes, route)
	}
	if ready.Status.IsExitNode {
		t.Errorf("Connector.Status.IsExitNode = true, want false")
	}
	if ready.Status.IsAppConnector {
		t.Errorf("Connector.Status.IsAppConnector = true, want false")
	}

	deviceID := deviceIDForConnector(t, cn.Name)
	if err := tstest.WaitFor(time.Minute, func() error {
		routes, err := tsClient.Devices().SubnetRoutes(t.Context(), deviceID)
		if err != nil {
			return fmt.Errorf("get subnet routes for %s: %w", deviceID, err)
		}
		if !slices.Contains(routes.Advertised, route) {
			return fmt.Errorf("device %s does not advertise %s: %v", deviceID, route, routes.Advertised)
		}
		if !slices.Contains(routes.Enabled, route) {
			return fmt.Errorf("route %s not yet enabled on device %s: %v", route, deviceID, routes.Enabled)
		}
		return nil
	}); err != nil {
		t.Fatalf("verifying subnet router routes: %v", err)
	}
}

// See [TestMain] for test requirements.
func TestConnectorMultiTailnet(t *testing.T) {
	if tnClient == nil || secondTNClient == nil {
		t.Skip("TestConnectorMultiTailnet requires a working tailnet client for a first and second tailnet")
	}

	t.Parallel()

	cn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("connector-multi-tn"),
		},
		Spec: tsapi.ConnectorSpec{
			Tailnet:    "second-tailnet",
			ExitNode:   true,
			ProxyClass: "default",
		},
	}
	createAndCleanup(t, kubeClient, cn)

	ready := waitForConnectorReady(t, cn.Name)
	if !ready.Status.IsExitNode {
		t.Errorf("Connector.Status.IsExitNode = false, want true")
	}

	if err := verifyConnectorTailnet(t, cn, secondTNClient); err != nil {
		t.Fatalf("verifying Connector %s is registered to the correct tailnet: %v", cn.Name, err)
	}

	deviceID := deviceIDForConnector(t, cn.Name)
	if err := tstest.WaitFor(time.Minute, func() error {
		dev, err := secondTSClient.Devices().GetWithAllFields(t.Context(), deviceID)
		if err != nil {
			return fmt.Errorf("get device %s via secondTSClient: %w", deviceID, err)
		}
		if !slices.Contains(dev.AdvertisedRoutes, "0.0.0.0/0") ||
			!slices.Contains(dev.AdvertisedRoutes, "::/0") {
			return fmt.Errorf("device %s does not advertise exit node routes: %v", deviceID, dev.AdvertisedRoutes)
		}
		return nil
	}); err != nil {
		t.Fatalf("verifying exit node advertisement on second tailnet: %v", err)
	}
}

func waitForConnectorReady(t *testing.T, name string) *tsapi.Connector {
	t.Helper()
	forceReconcile := triggerReconcile(t,
		client.ObjectKey{Name: name}, &tsapi.Connector{}, 30*time.Second)

	cn := &tsapi.Connector{}
	if err := tstest.WaitFor(5*time.Minute, func() error {
		forceReconcile()
		cn = &tsapi.Connector{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, cn); err != nil {
			return err
		}
		for _, c := range cn.Status.Conditions {
			if c.Type != string(tsapi.ConnectorReady) {
				continue
			}
			if c.Status != metav1.ConditionTrue {
				return fmt.Errorf("Connector %s not ready: %s: %s", name, c.Reason, c.Message)
			}
			if c.ObservedGeneration != cn.Generation {
				return fmt.Errorf("Connector %s: condition observedGeneration=%d, spec generation=%d",
					name, c.ObservedGeneration, cn.Generation)
			}
			if len(cn.Status.Devices) == 0 || cn.Status.Devices[0].Hostname == "" {
				return fmt.Errorf("Connector %s has no device info yet", name)
			}
			return nil
		}
		return fmt.Errorf("Connector %s has no ConnectorReady condition yet", name)
	}); err != nil {
		t.Fatalf("waiting for Connector %s to become ready: %v", name, err)
	}
	t.Logf("Connector %s is ready: %s", name, cn.Status.Hostname)
	return cn
}

func deviceIDForConnector(t *testing.T, name string) string {
	t.Helper()
	var id string
	if err := tstest.WaitFor(time.Minute, func() error {
		var secrets corev1.SecretList
		if err := kubeClient.List(t.Context(), &secrets,
			client.InNamespace("tailscale"),
			client.MatchingLabels{
				"tailscale.com/parent-resource-type": "connector",
				"tailscale.com/parent-resource":      name,
			},
		); err != nil {
			return err
		}
		if len(secrets.Items) == 0 {
			return fmt.Errorf("no state Secret for Connector %s yet", name)
		}
		id = string(secrets.Items[0].Data[kubetypes.KeyDeviceID])
		if id == "" {
			return fmt.Errorf("state Secret for Connector %s has no device_id yet", name)
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for Connector %s state Secret: %v", name, err)
	}
	return id
}
