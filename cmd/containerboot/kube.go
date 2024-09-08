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

// setupKube is responsible for doing any necessary configuration and checks to
// ensure that tailscale state storage and authentication mechanism will work on
// Kubernetes.
func (cfg *settings) setupKube(ctx context.Context) error {
	if cfg.KubeSecret == "" {
		return nil
	}
	canPatch, canCreate, err := kc.CheckSecretPermissions(ctx, cfg.KubeSecret)
	if err != nil {
		return fmt.Errorf("Some Kubernetes permissions are missing, please check your RBAC configuration: %v", err)
	}
	cfg.KubernetesCanPatch = canPatch

	s, err := kc.GetSecret(ctx, cfg.KubeSecret)
	if err != nil && kubeclient.IsNotFoundErr(err) && !canCreate {
		return fmt.Errorf("Tailscale state Secret %s does not exist and we don't have permissions to create it. "+
			"If you intend to store tailscale state elsewhere than a Kubernetes Secret, "+
			"you can explicitly set TS_KUBE_SECRET env var to an empty string. "+
			"Else ensure that RBAC is set up that allows the service account associated with this installation to create Secrets.", cfg.KubeSecret)
	} else if err != nil && !kubeclient.IsNotFoundErr(err) {
		return fmt.Errorf("Getting Tailscale state Secret %s: %v", cfg.KubeSecret, err)
	}

	if cfg.AuthKey == "" && !isOneStepConfig(cfg) {
		if s == nil {
			log.Print("TS_AUTHKEY not provided and kube secret does not exist, login will be interactive if needed.")
			return nil
		}
		keyBytes, _ := s.Data["authkey"]
		key := string(keyBytes)

		if key != "" {
			// This behavior of pulling authkeys from kube secrets was added
			// at the same time as the patch permission, so we can enforce
			// that we must be able to patch out the authkey after
			// authenticating if you want to use this feature. This avoids
			// us having to deal with the case where we might leave behind
			// an unnecessary reusable authkey in a secret, like a rake in
			// the grass.
			if !cfg.KubernetesCanPatch {
				return errors.New("authkey found in TS_KUBE_SECRET, but the pod doesn't have patch permissions on the secret to manage the authkey.")
			}
			cfg.AuthKey = key
		} else {
			log.Print("No authkey found in kube secret and TS_AUTHKEY not provided, login will be interactive if needed.")
		}
	}
	return nil
}

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
