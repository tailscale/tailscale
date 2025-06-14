// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	longReque = 60 * time.Second
)

var (
	errOperatorUntrusted = errors.New("operator key is not trusted by the network")
)

type tsLocalClient interface {
	NetworkLockStatus(ctx context.Context) (*ipnstate.NetworkLockStatus, error)
	NetworkLockSign(ctx context.Context, nodeKey key.NodePublic, verifier []byte) error
}

// NodeKeySignerReconciler is responsible for signing node keys for devices
// managed by the tailscale operator. It does this by watching for changes to
// secrets managed by the operator and signing the device node key with the
// operator's lock key. If the network is not locked, it does nothing.
type NodeKeySignerReconciler struct {
	client.Client
	logger        *zap.SugaredLogger
	tsLocalClient tsLocalClient
}

func (a *NodeKeySignerReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := a.logger.With("secret-namespace", req.Namespace, "secret-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	secret := new(corev1.Secret)
	err = a.Get(ctx, req.NamespacedName, secret)
	if apierrors.IsNotFound(err) {
		// Secret not found, could have been deleted after reconcile request.
		logger.Debugf("secret not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get secret: %w", err)
	}

	if !secret.DeletionTimestamp.IsZero() {
		// StatefulSet is being deleted, nothing to do.
		logger.Debugf("secret is being deleted, skipping")
		return reconcile.Result{}, nil
	}

	if !isManagedResource(secret) {
		logger.Debugf("secret is not managed by the tailscale operator, skipping")
		return reconcile.Result{}, nil
	}

	if done, err := a.signNodeKey(ctx, logger, secret); errors.Is(err, errOperatorUntrusted) {
		return reconcile.Result{RequeueAfter: longReque}, nil
	} else if !done {
		return reconcile.Result{RequeueAfter: shortRequeue}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to sign node key: %w", err)
	}

	return reconcile.Result{}, nil
}

// signNodeKey signs the device node key with the operator's lock key if the
// network is locked. It does nothing if the network is not locked or if the
// device node key is already signed.
// If the device is not ready to be signed yet and should be retried, it returns
// false. If the device is signed or an error occurs, it returns true.
func (a *NodeKeySignerReconciler) signNodeKey(ctx context.Context, logger *zap.SugaredLogger, secret *corev1.Secret) (bool, error) {
	deviceId := tailcfg.StableNodeID(secret.Data[kubetypes.KeyDeviceID])
	if deviceId.IsZero() {
		logger.Debug("NodeID is empty. It may not be populated yet")
		return false, nil
	}

	lockStatus, err := a.tsLocalClient.NetworkLockStatus(ctx)
	if err != nil {
		return true, fmt.Errorf("failed to get network lock status: %w", err)
	}

	if !lockStatus.Enabled {
		logger.Debugf("Tailnet is not locked, skipping node key signing")
		return true, nil
	}

	if findTKAPeerByStableID(lockStatus.VisiblePeers, deviceId) != nil {
		// Device is a visible peer, no need to sign its node key.
		return true, nil
	}

	// Check if the operator's lock key is trusted.
	if !slices.ContainsFunc(lockStatus.TrustedKeys, func(k ipnstate.TKAKey) bool {
		return lockStatus.PublicKey.Equal(k.Key)
	}) {
		logger.Warnf("Operator key is not trusted by the network. Add %q to the trusted signer keys", lockStatus.PublicKey.CLIString())
		return true, errOperatorUntrusted
	}

	devicePeer := findTKAPeerByStableID(lockStatus.FilteredPeers, deviceId)
	if devicePeer == nil {
		logger.Debugf("Device %q is not found in filtered peers list, deferring signing", deviceId)
		return false, nil
	}

	// Lock is enabled, but the device node key is not signed yet.
	logger.Infof("Network is locked. Attempting to sign device node key with operator key %q", lockStatus.PublicKey.CLIString())

	if err := a.tsLocalClient.NetworkLockSign(ctx, devicePeer.NodeKey, []byte(lockStatus.PublicKey.Verifier())); err != nil {
		return true, fmt.Errorf("failed to sign node key: %w", err)
	}

	return true, nil
}

func findTKAPeerByStableID(peers []*ipnstate.TKAPeer, deviceId tailcfg.StableNodeID) *ipnstate.TKAPeer {
	for _, p := range peers {
		if p.StableID == deviceId {
			return p
		}
	}
	return nil
}
