// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"strings"
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

const fieldManager = "tailscale-k8s-proxy"

// extractStateSecretName extracts the Kubernetes secret name from a state store
// path like "kube:secret-name".
func extractStateSecretName(statePath string) (string, error) {
	if !strings.HasPrefix(statePath, "kube:") {
		return "", fmt.Errorf("state path %q is not a kube store", statePath)
	}
	secretName := strings.TrimPrefix(statePath, "kube:")
	if secretName == "" {
		return "", fmt.Errorf("state path %q has no secret name", statePath)
	}
	return secretName, nil
}

// newKubeClient creates a kubeclient for interacting with the state Secret.
func newKubeClient(stateSecretName string) (kubeclient.Client, error) {
	kc, err := kubeclient.New(fieldManager)
	if err != nil {
		return nil, fmt.Errorf("error creating kube client: %w", err)
	}
	return kc, nil
}

// resetState clears containerboot/k8s-proxy state from previous runs and sets
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

	return kc.StrategicMergePatchSecret(ctx, stateSecretName, s, fieldManager)
}

// checkInitialAuthState checks if the tsnet server is in an auth failure state
// immediately after coming up. Returns true if auth key reissue is needed.
func checkInitialAuthState(ctx context.Context, lc *local.Client) (bool, error) {
	status, err := lc.Status(ctx)
	if err != nil {
		return false, fmt.Errorf("error getting status: %w", err)
	}

	if status.BackendState == ipn.NeedsLogin.String() {
		return true, nil
	}

	// Status.Health is a []string of health warnings.
	loginWarnableCode := string(health.LoginStateWarnable.Code)
	for _, h := range status.Health {
		if strings.Contains(h, loginWarnableCode) {
			return true, nil
		}
	}

	return false, nil
}

// monitorAuthHealth watches the IPN bus for auth failures and triggers reissue
// when needed. Runs until context is cancelled or auth failure is detected.
func monitorAuthHealth(ctx context.Context, lc *local.Client, kc kubeclient.Client, stateSecretName string, cfgChan <-chan *conf.Config, configPath string, authKey string, logger *zap.SugaredLogger) error {
	w, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialHealthState|ipn.NotifyInitialState)
	if err != nil {
		return fmt.Errorf("failed to watch IPN bus for auth health: %w", err)
	}
	defer w.Close()

	for {
		n, err := w.Next()
		if err != nil {
			if err == ctx.Err() {
				return nil
			}
			return err
		}

		if n.State != nil && *n.State == ipn.NeedsLogin {
			logger.Info("Auth key missing or invalid (NeedsLogin state), disconnecting from control and requesting new key from operator")
			return handleAuthKeyReissue(ctx, lc, kc, stateSecretName, authKey, cfgChan, logger)
		}

		if n.Health != nil {
			if _, ok := n.Health.Warnings[health.LoginStateWarnable.Code]; ok {
				logger.Info("Auth key failed to authenticate (may be expired or single-use), disconnecting from control and requesting new key from operator")
				return handleAuthKeyReissue(ctx, lc, kc, stateSecretName, authKey, cfgChan, logger)
			}
		}
	}
}

func clearTailscaledState(ctx context.Context, kc kubeclient.Client, stateSecretName string) error {
	secret, err := kc.GetSecret(ctx, stateSecretName)
	if err != nil {
		return fmt.Errorf("error reading state Secret: %w", err)
	}

	s := &kubeapi.Secret{
		Data: map[string][]byte{
			"_machinekey":      nil,
			"_current-profile": nil,
		},
	}

	// The profile key name is stored in _current-profile (e.g. "profile-a716").
	if profileKey := string(secret.Data["_current-profile"]); profileKey != "" {
		s.Data[profileKey] = nil
	}

	return kc.StrategicMergePatchSecret(ctx, stateSecretName, s, fieldManager)
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
	if err := authkey.SetReissueAuthKey(ctx, kc, stateSecretName, currentAuthKey); err != nil {
		return fmt.Errorf("failed to set reissue_authkey in Kubernetes Secret: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for auth key reissue")
		case cfg := <-cfgChan:
			if cfg.Parsed.AuthKey != nil && *cfg.Parsed.AuthKey != currentAuthKey {
				if err := authkey.ClearReissueAuthKey(ctx, kc, stateSecretName); err != nil {
					logger.Warnf("failed to clear reissue request: %v", err)
				}
				logger.Info("Successfully received new auth key, restarting to apply configuration")
				err := clearTailscaledState(ctx, kc, stateSecretName)
				if err != nil {
					return fmt.Errorf("failed to clear tailscaled state: %w", err)
				}
				return nil
			}
		}
	}
}
