// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"tailscale.com/client/local"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/kube/authkey"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
)

const k8sProxyFieldManager = "tailscale-k8s-proxy"

// resetState clears k8s-proxy state from previous runs and sets
// initial values. This ensures the operator doesn't use stale state when a Pod
// is first recreated.
//
// It also clears the reissue_authkey marker if the operator has actioned it
// (i.e., the config now has a different auth key than what was marked for
// reissue).
func resetState(ctx context.Context, kc kubeclient.Client, stateSecretName string, podUID string, configAuthKey string) error {
	existingSecret, err := kc.GetSecret(ctx, stateSecretName)
	switch {
	case kubeclient.IsNotFoundErr(err):
		return nil
	case err != nil:
		return fmt.Errorf("failed to read state Secret %q to reset state: %w", stateSecretName, err)
	}

	s := &kubeapi.Secret{
		Data: map[string][]byte{
			kubetypes.KeyCapVer: fmt.Appendf(nil, "%d", tailcfg.CurrentCapabilityVersion),
		},
	}
	if podUID != "" {
		s.Data[kubetypes.KeyPodUID] = []byte(podUID)
	}

	// Only clear reissue_authkey if the operator has actioned it.
	brokenAuthkey, ok := existingSecret.Data[kubetypes.KeyReissueAuthkey]
	if ok && configAuthKey != "" && string(brokenAuthkey) != configAuthKey {
		s.Data[kubetypes.KeyReissueAuthkey] = nil
	}

	return kc.StrategicMergePatchSecret(ctx, stateSecretName, s, k8sProxyFieldManager)
}

// needsAuthKeyReissue reports whether the given backend state and health
// warnings indicate a terminal auth failure requiring a new key from the
// operator.
func needsAuthKeyReissue(backendState string, healthWarnings []string) bool {
	if backendState == ipn.NeedsLogin.String() {
		return true
	}
	loginWarnableCode := string(health.LoginStateWarnable.Code)
	for _, h := range healthWarnings {
		if strings.Contains(h, loginWarnableCode) {
			return true
		}
	}
	return false
}

// checkInitialAuthState checks if the tsnet server is in an auth failure state
// immediately after coming up. Returns true if auth key reissue is needed.
func checkInitialAuthState(ctx context.Context, lc *local.Client) (bool, error) {
	status, err := lc.Status(ctx)
	if err != nil {
		return false, fmt.Errorf("error getting status: %w", err)
	}
	return needsAuthKeyReissue(status.BackendState, status.Health), nil
}

// monitorAuthHealth watches the IPN bus for auth failures and triggers reissue
// when needed. Runs until context is cancelled or auth failure is detected.
func monitorAuthHealth(ctx context.Context, lc *local.Client, reissueCh chan<- struct{}, logger *zap.SugaredLogger) error {
	w, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialHealthState)
	if err != nil {
		return fmt.Errorf("failed to watch IPN bus for auth health: %w", err)
	}
	defer w.Close()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := w.Next()
		if err != nil {
			return err
		}
		if n.Health != nil {
			if _, ok := n.Health.Warnings[health.LoginStateWarnable.Code]; ok {
				logger.Info("Auth key failed to authenticate (may be expired or single-use), requesting new key from operator")
				select {
				case reissueCh <- struct{}{}:
				case <-ctx.Done():
				}
				return nil
			}
		}
	}
}

// handleAuthKeyReissue orchestrates the auth key reissue flow:
// 1. Disconnect from control
// 2. Set reissue marker in state Secret
// 3. Wait for operator to provide new key
// 4. Exit cleanly (Kubernetes will restart the pod with the new key)
func handleAuthKeyReissue(ctx context.Context, lc *local.Client, kc kubeclient.Client, stateSecretName string, currentAuthKey string, cfgChan <-chan *conf.Config, logger *zap.SugaredLogger) error {
	if err := lc.DisconnectControl(ctx); err != nil {
		return fmt.Errorf("error disconnecting from control: %w", err)
	}
	if err := authkey.SetReissueAuthKey(ctx, kc, stateSecretName, currentAuthKey, k8sProxyFieldManager); err != nil {
		return fmt.Errorf("failed to set reissue_authkey in Kubernetes Secret: %w", err)
	}

	var mu sync.Mutex
	var latestAuthKey string
	notify := make(chan struct{}, 1)

	// we use this go func to abstract away conf.Config from the shared function
	go func() {
		for cfg := range cfgChan {
			if cfg.Parsed.AuthKey != nil {
				mu.Lock()
				latestAuthKey = *cfg.Parsed.AuthKey
				mu.Unlock()
				select {
				case notify <- struct{}{}:
				default:
				}
			}
		}
	}()

	getAuthKey := func() string {
		mu.Lock()
		defer mu.Unlock()
		return latestAuthKey
	}
	clearFn := func(ctx context.Context) error {
		return authkey.ClearReissueAuthKey(ctx, kc, stateSecretName, k8sProxyFieldManager)
	}

	return authkey.WaitForAuthKeyReissue(ctx, currentAuthKey, 10*time.Minute, getAuthKey, clearFn, notify)
}
