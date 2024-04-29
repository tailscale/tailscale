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

	"tailscale.com/kube"
	"tailscale.com/tailcfg"
)

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

var kc kube.Client

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
	if err != nil && kube.IsNotFoundErr(err) && !canCreate {
		return fmt.Errorf("Tailscale state Secret %s does not exist and we don't have permissions to create it. "+
			"If you intend to store tailscale state elsewhere than a Kubernetes Secret, "+
			"you can explicitly set TS_KUBE_SECRET env var to an empty string. "+
			"Else ensure that RBAC is set up that allows the service account associated with this installation to create Secrets.", cfg.KubeSecret)
	} else if err != nil && !kube.IsNotFoundErr(err) {
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
