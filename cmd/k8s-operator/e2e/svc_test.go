// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/client/tailscale/v2"
	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

// TestHAServiceCleanupOnAnnotationRemoved checks that removing the
// tailscale.com/proxy-group annotation from a Service that is exposed on a
// ProxyGroup cleans up the corresponding Tailscale Service and removes the
// operator's finalizer, rather than leaking the Tailscale Service and wedging
// the Service on delete.
func TestHAServiceCleanupOnAnnotationRemoved(t *testing.T) {
	if tsClient == nil {
		t.Skip("TestHAServiceCleanupOnAnnotationRemoved requires a working tailnet client")
	}
	t.Parallel()

	nginx := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, nginx)

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("ingress"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeIngress,
		},
	}
	createAndCleanup(t, kubeClient, pg)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("test-svc"),
			Namespace: ns,
			Annotations: map[string]string{
				"tailscale.com/proxy-group": pg.Name,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: new("tailscale"),
			Selector: map[string]string{
				"app.kubernetes.io/name": nginx.Name,
			},
			Ports: []corev1.ServicePort{
				{Name: "http", Protocol: "TCP", Port: 80},
			},
		},
	}
	createAndCleanup(t, kubeClient, svc)

	// The Tailscale Service is named after the Service's hostname, which
	// defaults to <namespace>-<name>.
	tsSvcName := fmt.Sprintf("svc:%s-%s", ns, svc.Name)

	forceReconcile := triggerReconcile(t,
		client.ObjectKey{Namespace: ns, Name: svc.Name},
		&corev1.Service{}, 30*time.Second)

	// Wait for the Service to be exposed and the Tailscale Service to exist.
	if err := tstest.WaitFor(5*time.Minute, func() error {
		forceReconcile()
		readySvc := &corev1.Service{ObjectMeta: objectMeta(ns, svc.Name)}
		if err := get(t.Context(), kubeClient, readySvc); err != nil {
			return err
		}
		for _, cond := range readySvc.Status.Conditions {
			if cond.Type == string(tsapi.IngressSvcConfigured) && cond.Status == metav1.ConditionTrue {
				if _, err := tsClient.VIPServices().Get(t.Context(), tsSvcName); err != nil {
					return fmt.Errorf("Tailscale Service %q not created yet: %w", tsSvcName, err)
				}
				return nil
			}
		}
		return fmt.Errorf("Service is not ready yet")
	}); err != nil {
		t.Fatalf("error waiting for the Service to become ready: %v", err)
	}

	// Remove the ProxyGroup annotation.
	readySvc := &corev1.Service{ObjectMeta: objectMeta(ns, svc.Name)}
	if err := get(t.Context(), kubeClient, readySvc); err != nil {
		t.Fatalf("getting Service: %v", err)
	}
	delete(readySvc.Annotations, "tailscale.com/proxy-group")
	if err := kubeClient.Update(t.Context(), readySvc); err != nil {
		t.Fatalf("removing proxy-group annotation: %v", err)
	}

	// The Tailscale Service must be cleaned up and the finalizer removed.
	if err := tstest.WaitFor(5*time.Minute, func() error {
		forceReconcile()
		if _, err := tsClient.VIPServices().Get(t.Context(), tsSvcName); err == nil {
			return fmt.Errorf("Tailscale Service %q still exists", tsSvcName)
		} else if !tailscale.IsNotFound(err) {
			return fmt.Errorf("unexpected error getting Tailscale Service %q: %w", tsSvcName, err)
		}
		cur := &corev1.Service{ObjectMeta: objectMeta(ns, svc.Name)}
		if err := get(t.Context(), kubeClient, cur); err != nil {
			return err
		}
		for _, f := range cur.Finalizers {
			if isServicePGFinalizerE2E(f) {
				return fmt.Errorf("service-pg finalizer %q not removed yet", f)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("error waiting for cleanup after annotation removal: %v", err)
	}
}

// isServicePGFinalizerE2E reports whether f is one of the HA Service
// reconciler's finalizers (either the ProxyGroup-encoded form or the bare
// legacy form). Kept local to the e2e package to avoid importing package main.
func isServicePGFinalizerE2E(f string) bool {
	_, name, ok := strings.Cut(f, "/")
	return ok && name == "service-pg-finalizer"
}

// TestServiceCleanupUnreportedDevice checks that cleaning up a proxy that
// registered with control but never reported its device ID deletes its device,
// found by machine key, and leaves every other device in the tailnet alone.
func TestServiceCleanupUnreportedDevice(t *testing.T) {
	if tsClient == nil {
		t.Skip("TestServiceCleanupUnreportedDevice requires a working tailnet client")
	}
	t.Parallel()

	// Fill the tailnet, so that if control ignored the machine key filter the
	// lookup would return many devices instead of one.
	const otherDevices = 25
	var otherIDs []string
	for range otherDevices {
		srv := newTailnetNode(t, tsClient, generateName("other"))
		lc, err := srv.LocalClient()
		if err != nil {
			t.Fatalf("getting local client: %v", err)
		}
		st, err := lc.StatusWithoutPeers(t.Context())
		if err != nil {
			t.Fatalf("getting status: %v", err)
		}
		otherIDs = append(otherIDs, string(st.Self.ID))
	}

	// The proxy only needs to register, so the Service needs no backends.
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("test-cleanup"),
			Namespace: ns,
			Annotations: map[string]string{
				"tailscale.com/expose": "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name": "none",
			},
			Ports: []corev1.ServicePort{
				{Name: "http", Protocol: "TCP", Port: 80},
			},
		},
	}
	createAndCleanup(t, kubeClient, svc)

	var sec corev1.Secret
	if err := tstest.WaitFor(5*time.Minute, func() error {
		var secrets corev1.SecretList
		if err := kubeClient.List(t.Context(), &secrets,
			client.InNamespace("tailscale"),
			client.MatchingLabels{
				"tailscale.com/parent-resource":      svc.Name,
				"tailscale.com/parent-resource-ns":   ns,
				"tailscale.com/parent-resource-type": "svc",
			},
		); err != nil {
			return err
		}
		if len(secrets.Items) == 0 {
			return fmt.Errorf("no state Secret for Service %s yet", svc.Name)
		}
		sec = secrets.Items[0]
		if len(sec.Data[kubetypes.KeyDeviceID]) == 0 {
			return fmt.Errorf("state Secret %s has no device_id yet", sec.Name)
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for the proxy to register: %v", err)
	}
	deviceID := string(sec.Data[kubetypes.KeyDeviceID])

	var mk key.MachinePrivate
	if err := mk.UnmarshalText(sec.Data[string(ipn.MachineKeyStateKey)]); err != nil {
		t.Fatalf("parsing machine key in state Secret %s: %v", sec.Name, err)
	}
	devices, err := tsClient.Devices().List(t.Context(), tailscale.WithFilter("machineKey", []string{mk.Public().String()}))
	if err != nil {
		t.Fatalf("listing devices by machine key: %v", err)
	}
	if len(devices) != 1 || devices[0].NodeID != deviceID {
		var ids []string
		for _, d := range devices {
			ids = append(ids, d.NodeID)
		}
		t.Fatalf("devices with the proxy's machine key = %v, want [%s]", ids, deviceID)
	}

	// Mimic a proxy that was shut down before its first netmap. containerboot
	// only writes device_id when it changes, so the running proxy won't
	// restore it.
	secPatch := client.RawPatch(types.MergePatchType, []byte(`{"data":{"device_id":null,"device_fqdn":null,"device_ips":null}}`))
	if err := kubeClient.Patch(t.Context(), &sec, secPatch); err != nil {
		t.Fatalf("removing device_id from state Secret %s: %v", sec.Name, err)
	}
	svcPatch := client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"annotations":{"tailscale.com/expose":null}}}`))
	if err := kubeClient.Patch(t.Context(), svc, svcPatch); err != nil {
		t.Fatalf("removing expose annotation: %v", err)
	}

	if err := tstest.WaitFor(5*time.Minute, func() error {
		cur := &corev1.Service{ObjectMeta: objectMeta(ns, svc.Name)}
		if err := get(t.Context(), kubeClient, cur); err != nil {
			return err
		}
		if slices.Contains(cur.Finalizers, "tailscale.com/finalizer") {
			return fmt.Errorf("Service %s cleanup not finished yet", svc.Name)
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for Service cleanup: %v", err)
	}

	_, err = tsClient.Devices().Get(t.Context(), deviceID)
	switch {
	case tailscale.IsNotFound(err):
	case err != nil:
		t.Fatalf("getting device %s: %v", deviceID, err)
	default:
		t.Fatalf("device %s is still in the tailnet after cleanup", deviceID)
	}

	devices, err = tsClient.Devices().List(t.Context())
	if err != nil {
		t.Fatalf("listing devices: %v", err)
	}
	remaining := make(set.Set[string])
	for _, d := range devices {
		remaining.Add(d.NodeID)
	}
	for _, id := range otherIDs {
		if !remaining.Contains(id) {
			t.Errorf("device %s was deleted, want only the proxy's device %s deleted", id, deviceID)
		}
	}
}
