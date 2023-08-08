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

	"tailscale.com/kube"
	"tailscale.com/tailcfg"
)

// findKeyInKubeSecret inspects the kube secret secretName for a data
// field called "authkey", and returns its value if present.
func findKeyInKubeSecret(ctx context.Context, secretName string) (string, error) {
	s, err := kc.GetSecret(ctx, secretName)
	if err != nil {
		return "", err
	}
	ak, ok := s.Data["authkey"]
	if !ok {
		return "", nil
	}
	return string(ak), nil
}

// storeDeviceInfo writes deviceID into the "device_id" data field of the kube
// secret secretName.
func storeDeviceInfo(ctx context.Context, secretName string, deviceID tailcfg.StableNodeID, fqdn string, addresses []netip.Prefix) error {
	// First check if the secret exists at all. Even if running on
	// kubernetes, we do not necessarily store state in a k8s secret.
	if _, err := kc.GetSecret(ctx, secretName); err != nil {
		if s, ok := err.(*kube.Status); ok {
			if s.Code >= 400 && s.Code <= 499 {
				// Assume the secret doesn't exist, or we don't have
				// permission to access it.
				return nil
			}
		}
		return err
	}

	var ips []string
	for _, addr := range addresses {
		ips = append(ips, addr.Addr().String())
	}
	deviceIPs, err := json.Marshal(ips)
	if err != nil {
		return err
	}

	m := &kube.Secret{
		Data: map[string][]byte{
			"device_id":   []byte(deviceID),
			"device_fqdn": []byte(fqdn),
			"device_ips":  deviceIPs,
		},
	}
	return kc.StrategicMergePatchSecret(ctx, secretName, m, "tailscale-container")
}

// deleteAuthKey deletes the 'authkey' field of the given kube
// secret. No-op if there is no authkey in the secret.
func deleteAuthKey(ctx context.Context, secretName string) error {
	// m is a JSON Patch data structure, see https://jsonpatch.com/ or RFC 6902.
	m := []kube.JSONPatch{
		{
			Op:   "remove",
			Path: "/data/authkey",
		},
	}
	if err := kc.JSONPatchSecret(ctx, secretName, m); err != nil {
		if s, ok := err.(*kube.Status); ok && s.Code == http.StatusUnprocessableEntity {
			// This is kubernetes-ese for "the field you asked to
			// delete already doesn't exist", aka no-op.
			return nil
		}
		return err
	}
	return nil
}

var kc *kube.Client

func initKube(root string) {
	if root != "/" {
		// If we are running in a test, we need to set the root path to the fake
		// service account directory.
		kube.SetRootPathForTesting(root)
	}
	var err error
	kc, err = kube.New()
	if err != nil {
		log.Fatalf("Error creating kube client: %v", err)
	}
	if root != "/" {
		// If we are running in a test, we need to set the URL to the
		// httptest server.
		kc.SetURL(fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")))
	}
}
