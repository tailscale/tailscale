// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"

	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
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

// storeCapVerUID stores the current capability version of tailscale and, if provided, UID of the Pod in the tailscale
// state Secret.
// These two fields are used by the Kubernetes Operator to observe the current capability version of tailscaled running in this container.
func (kc *kubeClient) storeCapVerUID(ctx context.Context, podUID string) error {
	capVerS := fmt.Sprintf("%d", tailcfg.CurrentCapabilityVersion)
	d := map[string][]byte{
		kubetypes.KeyCapVer: []byte(capVerS),
	}
	if podUID != "" {
		d[kubetypes.KeyPodUID] = []byte(podUID)
	}
	s := &kubeapi.Secret{
		Data: d,
	}
	return kc.StrategicMergePatchSecret(ctx, kc.stateSecret, s, "tailscale-container")
}
