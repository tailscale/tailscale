// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"encoding/json"
	"fmt"
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

const peerRelayServerPort uint16 = 41641

// See [TestMain] for test requirements.
func TestPeerRelay(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestPeerRelay requires a working tailnet client")
	}
	t.Parallel()

	pr := &tsapi.PeerRelay{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("peer-relay")},
		Spec: tsapi.PeerRelaySpec{
			ProxyClass: "default",
		},
	}
	createAndCleanup(t, kubeClient, pr)

	waitForPeerRelayConditionSet(t, pr.Name)
	verifyPeerRelayReplica(t, pr.Name, 0)
}

// See [TestMain] for test requirements.
func TestPeerRelayHA(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestPeerRelayHA requires a working tailnet client")
	}
	t.Parallel()

	const replicas int32 = 3
	pr := &tsapi.PeerRelay{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("peer-relay-ha")},
		Spec: tsapi.PeerRelaySpec{
			Replicas:   new(replicas),
			ProxyClass: "default",
		},
	}
	createAndCleanup(t, kubeClient, pr)

	waitForPeerRelayConditionSet(t, pr.Name)

	for i := int32(0); i < replicas; i++ {
		verifyPeerRelayReplica(t, pr.Name, i)
	}
}

func verifyPeerRelayReplica(t *testing.T, prName string, replica int32) {
	t.Helper()

	verifyPeerRelayConfigSecret(t, prName, replica)

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

func verifyPeerRelayConfigSecret(t *testing.T, prName string, replica int32) {
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
	if *conf.RelayServerPort != peerRelayServerPort {
		t.Fatalf("config Secret %s: RelayServerPort = %d, want %d", s.Name, *conf.RelayServerPort, peerRelayServerPort)
	}
}

// waitForPeerRelayConditionSet waits for the reconciler to stamp a PeerRelayReady condition that
// reflects the current generation. It deliberately does not assert the condition's status: the
// condition only goes True once every replica's LoadBalancer Service has an external address, and
// the kind cluster these tests run in has no cloud controller to assign one, so it is always False
// here. Once the suite can run against a cluster with a real LoadBalancer implementation this
// should assert metav1.ConditionTrue.
func waitForPeerRelayConditionSet(t *testing.T, prName string) {
	t.Helper()
	if err := tstest.WaitFor(3*time.Minute, func() error {
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
			return nil
		}
		return fmt.Errorf("PeerRelay %s has no PeerRelayReady condition yet", prName)
	}); err != nil {
		t.Fatalf("waiting for PeerRelay %s status: %v", prName, err)
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
