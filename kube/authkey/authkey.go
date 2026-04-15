// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package authkey provides shared logic for handling auth key reissue
// requests between tailnet clients (containerboot, k8s-proxy) and the
// operator.
//
// When a client fails to authenticate (expired key, single-use key already
// used), it signals the operator by setting a marker in its state Secret.
// The operator responds by deleting the old device and issuing a new auth
// key. The client watches for the new key and restarts to apply it.
package authkey

import (
	"context"
	"fmt"
	"log"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/conffile"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
)

const (
	TailscaleContainerFieldManager = "tailscale-container"
)

// SetReissueAuthKey sets the reissue_authkey marker in the state Secret to
// signal to the operator that a new auth key is needed. The marker value is
// the auth key that failed to authenticate.
func SetReissueAuthKey(ctx context.Context, kc kubeclient.Client, stateSecretName string, authKey string, fieldManager string) error {
	s := &kubeapi.Secret{
		Data: map[string][]byte{
			kubetypes.KeyReissueAuthkey: []byte(authKey),
		},
	}

	log.Printf("Requesting a new auth key from operator")
	return kc.StrategicMergePatchSecret(ctx, stateSecretName, s, fieldManager)
}

// ClearReissueAuthKey removes the reissue_authkey marker from the state Secret
// to signal to the operator that we've successfully received the new key.
func ClearReissueAuthKey(ctx context.Context, kc kubeclient.Client, stateSecretName string, fieldManager string) error {
	existing, err := kc.GetSecret(ctx, stateSecretName)
	if err != nil {
		return fmt.Errorf("error getting state secret: %w", err)
	}

	s := &kubeapi.Secret{
		Data: map[string][]byte{
			kubetypes.KeyReissueAuthkey:        nil,
			kubetypes.KeyDeviceID:              nil,
			kubetypes.KeyDeviceFQDN:            nil,
			kubetypes.KeyDeviceIPs:             nil,
			string(ipn.MachineKeyStateKey):     nil,
			string(ipn.CurrentProfileStateKey): nil,
			string(ipn.KnownProfilesStateKey):  nil,
		},
	}

	if profileKey := string(existing.Data[string(ipn.CurrentProfileStateKey)]); profileKey != "" {
		s.Data[profileKey] = nil
	}

	return kc.StrategicMergePatchSecret(ctx, stateSecretName, s, fieldManager)
}

// WaitForAuthKeyReissue polls getAuthKey for a new auth key different from
// oldAuthKey, returning when one is found or maxWait expires. If notify is
// non-nil, it is used to wake the loop on config changes; otherwise it falls
// back to periodic polling. The clearFn callback is called when a new key is
// detected, to clear the reissue marker from the state Secret.
func WaitForAuthKeyReissue(ctx context.Context, oldAuthKey string, maxWait time.Duration, getAuthKey func() string, clearFn func(context.Context) error, notify <-chan struct{}) error {
	log.Printf("Waiting for operator to provide new auth key (max wait: %v)", maxWait)

	ctx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	pollInterval := 5 * time.Second
	pt := time.NewTicker(pollInterval)
	defer pt.Stop()

	start := time.Now()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for auth key reissue after %v", maxWait)
		case <-pt.C:
		case <-notify:
		}

		newAuthKey := getAuthKey()
		if newAuthKey != "" && newAuthKey != oldAuthKey {
			log.Printf("New auth key received from operator after %v", time.Since(start).Round(time.Second))
			if err := clearFn(ctx); err != nil {
				log.Printf("Warning: failed to clear reissue request: %v", err)
			}
			return nil
		}

		if notify == nil {
			log.Printf("Waiting for new auth key from operator (%v elapsed)", time.Since(start).Round(time.Second))
		}
	}
}

// AuthKeyFromConfig extracts the auth key from a tailscaled config file.
// Returns empty string if the file cannot be read or contains no auth key.
func AuthKeyFromConfig(path string) string {
	if cfg, err := conffile.Load(path); err == nil && cfg.Parsed.AuthKey != nil {
		return *cfg.Parsed.AuthKey
	}

	return ""
}
