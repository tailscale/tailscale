// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"

	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/tailcfg"
)

// storeDeviceID writes deviceID to 'device_id' data field of the named
// Kubernetes Secret.
func storeDeviceID(ctx context.Context, secretName string, deviceID tailcfg.StableNodeID) error {
	s := &kubeapi.Secret{
		Data: map[string][]byte{
			"device_id": []byte(deviceID),
		},
	}
	return kc.StrategicMergePatchSecret(ctx, secretName, s, "tailscale-container")
}

// storeDeviceEndpoints writes device's tailnet IPs and MagicDNS name to fields
// 'device_ips', 'device_fqdn' of the named Kubernetes Secret.
func storeDeviceEndpoints(ctx context.Context, secretName string, fqdn string, addresses []netip.Prefix) error {
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
			"device_fqdn": []byte(fqdn),
			"device_ips":  deviceIPs,
		},
	}
	return kc.StrategicMergePatchSecret(ctx, secretName, s, "tailscale-container")
}

// deleteAuthKey deletes the 'authkey' field of the given kube
// secret. No-op if there is no authkey in the secret.
func deleteAuthKey(ctx context.Context, secretName string) error {
	// m is a JSON Patch data structure, see https://jsonpatch.com/ or RFC 6902.
	m := []kubeclient.JSONPatch{
		{
			Op:   "remove",
			Path: "/data/authkey",
		},
	}
	if err := kc.JSONPatchSecret(ctx, secretName, m); err != nil {
		if s, ok := err.(*kubeapi.Status); ok && s.Code == http.StatusUnprocessableEntity {
			// This is kubernetes-ese for "the field you asked to
			// delete already doesn't exist", aka no-op.
			return nil
		}
		return err
	}
	return nil
}

var kc kubeclient.Client

func initKubeClient(root string) {
	if root != "/" {
		// If we are running in a test, we need to set the root path to the fake
		// service account directory.
		kubeclient.SetRootPathForTesting(root)
	}
	var err error
	kc, err = kubeclient.New()
	if err != nil {
		log.Fatalf("Error creating kube client: %v", err)
	}
	if (root != "/") || os.Getenv("TS_KUBERNETES_READ_API_SERVER_ADDRESS_FROM_ENV") == "true" {
		// Derive the API server address from the environment variables
		// Used to set http server in tests, or optionally enabled by flag
		kc.SetURL(fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")))
	}
}
