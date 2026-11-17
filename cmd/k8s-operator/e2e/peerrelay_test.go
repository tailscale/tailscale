// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
)

const defaultPeerRelayPort uint16 = 41641

// See [TestMain] for test requirements.
func TestPeerRelay(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestPeerRelay requires a working tailnet client")
	}
	t.Parallel()

	const port uint16 = 6969
	staticEndpoints := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:6969")}

	pr := &tsapi.PeerRelay{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("peer-relay")},
		Spec: tsapi.PeerRelaySpec{
			ProxyClass:      "default",
			Service:         &tsapi.PeerRelayService{Port: new(port)},
			StaticEndpoints: []string{"203.0.113.10:6969"},
		},
	}
	createAndCleanup(t, kubeClient, pr)

	waitForPeerRelayReady(t, pr.Name)
	verifyPeerRelayStatusEndpoints(t, pr.Name, 1, staticEndpoints)
	verifyPeerRelayReplica(t, pr.Name, 0, port, staticEndpoints)
}

// See [TestMain] for test requirements.
func TestPeerRelayHA(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestPeerRelayHA requires a working tailnet client")
	}
	t.Parallel()

	const replicas int32 = 3
	staticEndpoints := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.20:41641")}

	pr := &tsapi.PeerRelay{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("peer-relay-ha")},
		Spec: tsapi.PeerRelaySpec{
			Replicas:        new(replicas),
			ProxyClass:      "default",
			StaticEndpoints: []string{"203.0.113.20:41641"},
		},
	}
	createAndCleanup(t, kubeClient, pr)

	waitForPeerRelayReady(t, pr.Name)
	verifyPeerRelayStatusEndpoints(t, pr.Name, replicas, staticEndpoints)

	for i := range replicas {
		verifyPeerRelayReplica(t, pr.Name, i, defaultPeerRelayPort, staticEndpoints)
	}
}

func verifyPeerRelayReplica(t *testing.T, prName string, replica int32, wantPort uint16, wantStaticEndpoints []netip.AddrPort) {
	t.Helper()

	verifyPeerRelayConfigSecret(t, prName, replica, wantPort, wantStaticEndpoints)

	deviceID, tailnetIPs := waitForPeerRelayDeviceInfo(t, prName, replica)

	wantHostname := fmt.Sprintf("%s-%d", prName, replica)
	if err := tstest.WaitFor(2*time.Minute, func() error {
		dev, err := tsClient.Devices().Get(t.Context(), deviceID)
		if err != nil {
			return fmt.Errorf("get device %s: %w", deviceID, err)
		}
		if dev.Hostname != wantHostname {
			return fmt.Errorf("device %s hostname = %q, want %q", deviceID, dev.Hostname, wantHostname)
		}

		if !dev.ConnectedToControl {
			return fmt.Errorf("device %s not connected to control", deviceID)
		}

		return nil
	}); err != nil {
		t.Fatalf("verifying device %s via tsClient: %v", deviceID, err)
	}

	t.Logf("PeerRelay %s replica %d: device %s, tailnet IPs %v", prName, replica, deviceID, tailnetIPs)
}

func verifyPeerRelayConfigSecret(t *testing.T, prName string, replica int32, wantPort uint16, wantStaticEndpoints []netip.AddrPort) {
	t.Helper()

	var secrets corev1.SecretList
	if err := kubeClient.List(t.Context(), &secrets,
		client.InNamespace("tailscale"),
		client.MatchingLabels{
			"tailscale.com/parent-resource-type": "peerrelay",
			"tailscale.com/parent-resource":      prName,
			kubetypes.LabelSecretType:            kubetypes.LabelSecretTypeConfig,
			"tailscale.com/peer-relay-replica":   strconv.FormatInt(int64(replica), 10),
		},
	); err != nil {
		t.Fatalf("listing config Secret for PeerRelay %s replica %d: %v", prName, replica, err)
	}
	if len(secrets.Items) == 0 {
		t.Fatalf("no config Secret for PeerRelay %s replica %d", prName, replica)
	}
	s := secrets.Items[0]

	var confBody []byte
	for name, body := range s.Data {
		if strings.HasPrefix(name, "cap-") && strings.HasSuffix(name, ".hujson") {
			confBody = body
			break
		}
	}
	if len(confBody) == 0 {
		var keys []string
		for k := range s.Data {
			keys = append(keys, k)
		}
		t.Fatalf("config Secret %s has no cap-<v>.hujson data key: got %v", s.Name, keys)
	}

	var conf ipn.ConfigVAlpha
	if err := json.Unmarshal(confBody, &conf); err != nil {
		t.Fatalf("config Secret %s: parsing config: %v", s.Name, err)
	}
	if conf.RelayServerPort == nil {
		t.Fatalf("config Secret %s: RelayServerPort not set; tailscaled would not run as a peer relay", s.Name)
	}
	if *conf.RelayServerPort != wantPort {
		t.Fatalf("config Secret %s: RelayServerPort = %d, want %d", s.Name, *conf.RelayServerPort, wantPort)
	}
	// The kind cluster's LoadBalancer Services never get an address, so the config's advertised endpoints must be
	// exactly the spec's static endpoints.
	if !slices.Equal(conf.RelayServerStaticEndpoints, wantStaticEndpoints) {
		t.Fatalf("config Secret %s: RelayServerStaticEndpoints = %v, want %v", s.Name, conf.RelayServerStaticEndpoints, wantStaticEndpoints)
	}
}

// waitForPeerRelayReady waits for the reconciler to stamp a PeerRelayReady condition that reflects the current
// generation and reports True. Readiness needs every replica to have an endpoint, which spec.staticEndpoints
// provides despite the kind cluster's LoadBalancer Services never getting an address, and every pod to be ready.
func waitForPeerRelayReady(t *testing.T, prName string) {
	t.Helper()
	if err := tstest.WaitFor(5*time.Minute, func() error {
		pr := &tsapi.PeerRelay{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: prName}, pr); err != nil {
			return err
		}
		for _, c := range pr.Status.Conditions {
			if c.Type != string(tsapi.PeerRelayReady) {
				continue
			}
			if c.ObservedGeneration != pr.Generation {
				return fmt.Errorf("PeerRelay %s condition observedGeneration=%d, spec generation=%d",
					prName, c.ObservedGeneration, pr.Generation)
			}
			if c.Status != metav1.ConditionTrue {
				return fmt.Errorf("PeerRelay %s not ready: reason=%s message=%q", prName, c.Reason, c.Message)
			}
			return nil
		}
		return fmt.Errorf("PeerRelay %s has no PeerRelayReady condition yet", prName)
	}); err != nil {
		t.Fatalf("waiting for PeerRelay %s to become ready: %v", prName, err)
	}
}

// verifyPeerRelayStatusEndpoints asserts that every replica's status.endpoints entries are exactly the spec's
// static endpoints. The kind cluster's LoadBalancer Services never get an address, so nothing else may appear.
func verifyPeerRelayStatusEndpoints(t *testing.T, prName string, replicas int32, want []netip.AddrPort) {
	t.Helper()

	pr := &tsapi.PeerRelay{}
	if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: prName}, pr); err != nil {
		t.Fatalf("getting PeerRelay %s: %v", prName, err)
	}

	for i := range replicas {
		var got []netip.AddrPort
		for _, ep := range pr.Status.Endpoints {
			if ep.Replica != i {
				continue
			}

			addr, err := netip.ParseAddr(ep.Address)
			if err != nil {
				t.Errorf("PeerRelay %s replica %d: status endpoint address %q does not parse: %v", prName, i, ep.Address, err)
				continue
			}
			got = append(got, netip.AddrPortFrom(addr, uint16(ep.Port)))
		}

		if !slices.Equal(got, want) {
			t.Errorf("PeerRelay %s replica %d: status.endpoints = %v, want %v", prName, i, got, want)
		}
	}
}

func waitForPeerRelayDeviceInfo(t *testing.T, prName string, replica int32) (deviceID string, tailnetIPs []string) {
	t.Helper()
	if err := tstest.WaitFor(5*time.Minute, func() error {
		var secrets corev1.SecretList
		if err := kubeClient.List(t.Context(), &secrets,
			client.InNamespace("tailscale"),
			client.MatchingLabels{
				"tailscale.com/parent-resource-type": "peerrelay",
				"tailscale.com/parent-resource":      prName,
				kubetypes.LabelSecretType:            kubetypes.LabelSecretTypeState,
				"tailscale.com/peer-relay-replica":   strconv.FormatInt(int64(replica), 10),
			},
		); err != nil {
			return err
		}
		if len(secrets.Items) == 0 {
			return fmt.Errorf("no state Secret for PeerRelay %s replica %d yet", prName, replica)
		}

		s := secrets.Items[0]
		deviceID = string(s.Data[kubetypes.KeyDeviceID])
		if deviceID == "" {
			return fmt.Errorf("state Secret %s has no device_id yet", s.Name)
		}

		rawIPs := s.Data[kubetypes.KeyDeviceIPs]
		if len(rawIPs) == 0 {
			return fmt.Errorf("state Secret %s has no device_ips yet", s.Name)
		}

		if err := json.Unmarshal(rawIPs, &tailnetIPs); err != nil {
			return fmt.Errorf("state Secret %s device_ips %q: %w", s.Name, string(rawIPs), err)
		}
		if len(tailnetIPs) == 0 {
			return fmt.Errorf("state Secret %s has empty device_ips list", s.Name)
		}

		return nil
	}); err != nil {
		t.Fatalf("waiting for state Secret for PeerRelay %s replica %d: %v", prName, replica, err)
	}
	return deviceID, tailnetIPs
}
