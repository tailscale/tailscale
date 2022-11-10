// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// findKeyInKubeSecret inspects the kube secret secretName for a data
// field called "authkey", and returns its value if present.
func findKeyInKubeSecret(ctx context.Context, secretName string) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", kubeNamespace, secretName), nil)
	if err != nil {
		return "", err
	}
	resp, err := doKubeRequest(ctx, req)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			// Kube secret doesn't exist yet, can't have an authkey.
			return "", nil
		}
		return "", err
	}
	defer resp.Body.Close()

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// We use a map[string]any here rather than import corev1.Secret,
	// because we only do very limited things to the secret, and
	// importing corev1 adds 12MiB to the compiled binary.
	var s map[string]any
	if err := json.Unmarshal(bs, &s); err != nil {
		return "", err
	}
	if d, ok := s["data"].(map[string]any); ok {
		if v, ok := d["authkey"].(string); ok {
			bs, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return "", err
			}
			return string(bs), nil
		}
	}
	return "", nil
}

// storeDeviceID writes deviceID into the "device_id" data field of
// the kube secret secretName.
func storeDeviceID(ctx context.Context, secretName, deviceID string) error {
	// First check if the secret exists at all. Even if running on
	// kubernetes, we do not necessarily store state in a k8s secret.
	req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", kubeNamespace, secretName), nil)
	if err != nil {
		return err
	}
	resp, err := doKubeRequest(ctx, req)
	if err != nil {
		if resp != nil && resp.StatusCode >= 400 && resp.StatusCode <= 499 {
			// Assume the secret doesn't exist, or we don't have
			// permission to access it.
			return nil
		}
		return err
	}

	m := map[string]map[string]string{
		"stringData": map[string]string{
			"device_id": deviceID,
		},
	}
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(m); err != nil {
		return err
	}
	req, err = http.NewRequest("PATCH", fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s?fieldManager=tailscale-container", kubeNamespace, secretName), &b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	if _, err := doKubeRequest(ctx, req); err != nil {
		return err
	}
	return nil
}

// deleteAuthKey deletes the 'authkey' field of the given kube
// secret. No-op if there is no authkey in the secret.
func deleteAuthKey(ctx context.Context, secretName string) error {
	// m is a JSON Patch data structure, see https://jsonpatch.com/ or RFC 6902.
	m := []struct {
		Op   string `json:"op"`
		Path string `json:"path"`
	}{
		{
			Op:   "remove",
			Path: "/data/authkey",
		},
	}
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(m); err != nil {
		return err
	}
	req, err := http.NewRequest("PATCH", fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s?fieldManager=tailscale-container", kubeNamespace, secretName), &b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json-patch+json")
	if resp, err := doKubeRequest(ctx, req); err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnprocessableEntity {
			// This is kubernetes-ese for "the field you asked to
			// delete already doesn't exist", aka no-op.
			return nil
		}
		return err
	}
	return nil
}

var (
	kubeHost      string
	kubeNamespace string
	kubeToken     string
	kubeHTTP      *http.Transport
)

func initKube(root string) {
	// If running in Kubernetes, set things up so that doKubeRequest
	// can talk successfully to the kube apiserver.
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return
	}

	kubeHost = os.Getenv("KUBERNETES_SERVICE_HOST") + ":" + os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")

	bs, err := os.ReadFile(filepath.Join(root, "var/run/secrets/kubernetes.io/serviceaccount/namespace"))
	if err != nil {
		log.Fatalf("Error reading kube namespace: %v", err)
	}
	kubeNamespace = strings.TrimSpace(string(bs))

	bs, err = os.ReadFile(filepath.Join(root, "var/run/secrets/kubernetes.io/serviceaccount/token"))
	if err != nil {
		log.Fatalf("Error reading kube token: %v", err)
	}
	kubeToken = strings.TrimSpace(string(bs))

	bs, err = os.ReadFile(filepath.Join(root, "var/run/secrets/kubernetes.io/serviceaccount/ca.crt"))
	if err != nil {
		log.Fatalf("Error reading kube CA cert: %v", err)
	}
	cp := x509.NewCertPool()
	cp.AppendCertsFromPEM(bs)
	kubeHTTP = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: cp,
		},
		IdleConnTimeout: time.Second,
	}
}

// doKubeRequest sends r to the kube apiserver.
func doKubeRequest(ctx context.Context, r *http.Request) (*http.Response, error) {
	if kubeHTTP == nil {
		panic("not in kubernetes")
	}

	r.URL.Scheme = "https"
	r.URL.Host = kubeHost
	r.Header.Set("Authorization", "Bearer "+kubeToken)
	r.Header.Set("Accept", "application/json")

	resp, err := kubeHTTP.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("got non-200 status code %d", resp.StatusCode)
	}
	return resp, nil
}
