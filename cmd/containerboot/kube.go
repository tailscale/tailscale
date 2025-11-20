// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/ingressservices"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
	"tailscale.com/util/set"
)

// kubeClient is a wrapper around Tailscale's internal kube client that knows how to talk to the kube API server. We use
// this rather than any of the upstream Kubernetes client libaries to avoid extra imports.
type kubeClient struct {
	kubeclient.Client
	stateSecret string
	canPatch    bool // whether the client has permissions to patch Kubernetes Secrets
}

func newKubeClient(root string, stateSecret string) (*kubeClient, error) {
	if root != "/" {
		// If we are running in a test, we need to set the root path to the fake
		// service account directory.
		kubeclient.SetRootPathForTesting(root)
	}
	var err error
	kc, err := kubeclient.New("tailscale-container")
	if err != nil {
		return nil, fmt.Errorf("Error creating kube client: %w", err)
	}
	if (root != "/") || os.Getenv("TS_KUBERNETES_READ_API_SERVER_ADDRESS_FROM_ENV") == "true" {
		// Derive the API server address from the environment variables
		// Used to set http server in tests, or optionally enabled by flag
		kc.SetURL(fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")))
	}
	return &kubeClient{Client: kc, stateSecret: stateSecret}, nil
}

// storeDeviceID writes deviceID to 'device_id' data field of the client's state Secret.
func (kc *kubeClient) storeDeviceID(ctx context.Context, deviceID tailcfg.StableNodeID) error {
	s := &kubeapi.Secret{
		Data: map[string][]byte{
			kubetypes.KeyDeviceID: []byte(deviceID),
		},
	}
	return kc.StrategicMergePatchSecret(ctx, kc.stateSecret, s, "tailscale-container")
}

// storeDeviceEndpoints writes device's tailnet IPs and MagicDNS name to fields 'device_ips', 'device_fqdn' of client's
// state Secret.
func (kc *kubeClient) storeDeviceEndpoints(ctx context.Context, fqdn string, addresses []netip.Prefix) error {
	var ips []string
	for _, addr := range addresses {
		ips = append(ips, addr.Addr().String())
	}
	deviceIPs, err := json.Marshal(ips)
	if err != nil {
		return err
	}

	s := &kubeapi.Secret{
		Data: map[string][]byte{
			kubetypes.KeyDeviceFQDN: []byte(fqdn),
			kubetypes.KeyDeviceIPs:  deviceIPs,
		},
	}
	return kc.StrategicMergePatchSecret(ctx, kc.stateSecret, s, "tailscale-container")
}

// storeHTTPSEndpoint writes an HTTPS endpoint exposed by this device via 'tailscale serve' to the client's state
// Secret. In practice this will be the same value that gets written to 'device_fqdn', but this should only be called
// when the serve config has been successfully set up.
func (kc *kubeClient) storeHTTPSEndpoint(ctx context.Context, ep string) error {
	s := &kubeapi.Secret{
		Data: map[string][]byte{
			kubetypes.KeyHTTPSEndpoint: []byte(ep),
		},
	}
	return kc.StrategicMergePatchSecret(ctx, kc.stateSecret, s, "tailscale-container")
}

// deleteAuthKey deletes the 'authkey' field of the given kube
// secret. No-op if there is no authkey in the secret.
func (kc *kubeClient) deleteAuthKey(ctx context.Context) error {
	// m is a JSON Patch data structure, see https://jsonpatch.com/ or RFC 6902.
	m := []kubeclient.JSONPatch{
		{
			Op:   "remove",
			Path: "/data/authkey",
		},
	}
	if err := kc.JSONPatchResource(ctx, kc.stateSecret, kubeclient.TypeSecrets, m); err != nil {
		if s, ok := err.(*kubeapi.Status); ok && s.Code == http.StatusUnprocessableEntity {
			// This is kubernetes-ese for "the field you asked to
			// delete already doesn't exist", aka no-op.
			return nil
		}
		return err
	}
	return nil
}

// resetContainerbootState resets state from previous runs of containerboot to
// ensure the operator doesn't use stale state when a Pod is first recreated.
func (kc *kubeClient) resetContainerbootState(ctx context.Context, podUID string) error {
	existingSecret, err := kc.GetSecret(ctx, kc.stateSecret)
	switch {
	case kubeclient.IsNotFoundErr(err):
		// In the case that the Secret doesn't exist, we don't have any state to reset and can return early.
		return nil
	case err != nil:
		return fmt.Errorf("failed to read state Secret %q to reset state: %w", kc.stateSecret, err)
	}
	s := &kubeapi.Secret{
		Data: map[string][]byte{
			kubetypes.KeyCapVer: fmt.Appendf(nil, "%d", tailcfg.CurrentCapabilityVersion),
		},
	}
	if podUID != "" {
		s.Data[kubetypes.KeyPodUID] = []byte(podUID)
	}

	toClear := set.SetOf([]string{
		kubetypes.KeyDeviceID,
		kubetypes.KeyDeviceFQDN,
		kubetypes.KeyDeviceIPs,
		kubetypes.KeyHTTPSEndpoint,
		egressservices.KeyEgressServices,
		ingressservices.IngressConfigKey,
	})
	for key := range existingSecret.Data {
		if toClear.Contains(key) {
			// It's fine to leave the key in place as a debugging breadcrumb,
			// it should get a new value soon.
			s.Data[key] = nil
		}
	}

	return kc.StrategicMergePatchSecret(ctx, kc.stateSecret, s, "tailscale-container")
}

// waitForConsistentState waits for tailscaled to finish writing state if it
// looks like it's started. It is designed to reduce the likelihood that
// tailscaled gets shut down in the window between authenticating to control
// and finishing writing state. However, it's not bullet proof because we can't
// atomically authenticate and write state.
func (kc *kubeClient) waitForConsistentState(ctx context.Context) error {
	var logged bool

	bo := backoff.NewBackoff("", logger.Discard, 2*time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		secret, err := kc.GetSecret(ctx, kc.stateSecret)
		if ctx.Err() != nil || kubeclient.IsNotFoundErr(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("getting Secret %q: %v", kc.stateSecret, err)
		}

		if hasConsistentState(secret.Data) {
			return nil
		}

		if !logged {
			log.Printf("Waiting for tailscaled to finish writing state to Secret %q", kc.stateSecret)
			logged = true
		}
		bo.BackOff(ctx, errors.New("")) // Fake error to trigger actual sleep.
	}
}

// hasConsistentState returns true is there is either no state or the full set
// of expected keys are present.
func hasConsistentState(d map[string][]byte) bool {
	var (
		_, hasCurrent = d[string(ipn.CurrentProfileStateKey)]
		_, hasKnown   = d[string(ipn.KnownProfilesStateKey)]
		_, hasMachine = d[string(ipn.MachineKeyStateKey)]
		hasProfile    bool
	)

	for k := range d {
		if strings.HasPrefix(k, "profile-") {
			if hasProfile {
				return false // We only expect one profile.
			}
			hasProfile = true
		}
	}

	// Approximate check, we don't want to reimplement all of profileManager.
	return (hasCurrent && hasKnown && hasMachine && hasProfile) ||
		(!hasCurrent && !hasKnown && !hasMachine && !hasProfile)
}
