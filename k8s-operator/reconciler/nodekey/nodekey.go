// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package nodekey provides reconciliation logic for signing the node keys of devices managed by the operator when
// the tailnet has Tailnet Lock enabled. It watches the state Secrets of operator-managed proxies and, once a device
// has been registered, signs its node key with the operator's own lock key. If the tailnet is not locked, it does
// nothing.
package nodekey

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	reconcilerName = "nodekey-reconciler"

	currentProfileKey = "_current-profile"

	// requeueInterval is how often to recheck a device that can't be signed yet for reasons outside its state
	// Secret, such as an untrusted operator key or a device missing from the operator's netmap.
	// Reconciles are typically triggered by a change to the device's state Secret; this serves as a polling
	// fallback for instances where the key cannot be signed yet.
	requeueInterval = 60 * time.Second
)

type (
	// The LocalClient interface describes the subset of the operator's local tailscaled API used to inspect Tailnet
	// Lock state and sign node keys.
	LocalClient interface {
		TailnetLockStatus(ctx context.Context) (*ipnstate.TailnetLockStatus, error)
		TailnetLockSign(ctx context.Context, nodeKey key.NodePublic, rotationPublic []byte) error
	}

	// The ReconcilerOptions type contains configuration values for the Reconciler.
	ReconcilerOptions struct {
		// The client for interacting with the Kubernetes API.
		Client client.Client
		// The namespace in which the operator stores proxy state Secrets.
		TailscaleNamespace string
		// The client for interacting with the operator's local tailscaled.
		LocalClient LocalClient
		// The logger to use for this Reconciler.
		Logger *zap.SugaredLogger
	}
)

// NewReconciler returns a new instance of the Reconciler type. It watches for changes to operator-managed Secrets
// within the TailscaleNamespace. The ReconcilerOptions can be used to modify the behaviour of the Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	return &Reconciler{
		Client:      options.Client,
		logger:      options.Logger.Named(reconcilerName),
		localClient: options.LocalClient,
		tsNamespace: options.TailscaleNamespace,
	}
}

// Reconciler is responsible for signing node keys for devices
// managed by the tailscale operator. It does this by watching for changes to
// secrets managed by the operator and signing the device node key with the
// operator's lock key. If the network is not locked, it does nothing.
type Reconciler struct {
	client.Client
	logger      *zap.SugaredLogger
	localClient LocalClient
	tsNamespace string
}

// Register the Reconciler onto the given manager.Manager implementation.
func (r *Reconciler) Register(mgr manager.Manager) error {
	secretFilter := handler.EnqueueRequestsFromMapFunc(managedSecretHandler(r.tsNamespace))
	return builder.
		ControllerManagedBy(mgr).
		Named(reconcilerName).
		Watches(&corev1.Secret{}, secretFilter).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.logger.With("secret-namespace", req.Namespace, "secret-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	secret := new(corev1.Secret)
	err := r.Get(ctx, req.NamespacedName, secret)
	if apierrors.IsNotFound(err) {
		// Secret not found, could have been deleted after reconcile request.
		logger.Debugf("secret not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get secret: %w", err)
	}

	if !secret.DeletionTimestamp.IsZero() {
		// Secret is being deleted, nothing to do.
		logger.Debugf("secret is being deleted, skipping")
		return reconcile.Result{}, nil
	}

	return r.signNodeKey(ctx, logger, secret)
}

// signNodeKey signs the device node key with the operator's lock key if the
// network is locked. It does nothing if the network is not locked or if the
// device node key is already signed.
func (r *Reconciler) signNodeKey(ctx context.Context, logger *zap.SugaredLogger, secret *corev1.Secret) (reconcile.Result, error) {
	deviceID := tailcfg.StableNodeID(secret.Data[kubetypes.KeyDeviceID])
	if deviceID.IsZero() {
		logger.Debug("NodeID is empty. It may not be populated yet")
		return reconcile.Result{}, nil
	}

	nodeKey, err := getDeviceKey(secret)
	if err != nil {
		return reconcile.Result{}, err
	} else if nodeKey.IsZero() {
		logger.Debugf("Device %q state Secret does not contain a node key in its IPN profile; waiting for update", deviceID)
		// No requeue; wait for state Secret watch to trigger.
		return reconcile.Result{}, nil
	}

	lockStatus, err := r.localClient.TailnetLockStatus(ctx)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailnet lock status: %w", err)
	}

	if !lockStatus.Enabled {
		logger.Debugf("Tailnet is not locked, skipping node key signing")
		return reconcile.Result{}, nil
	}

	if findTKAPeerByStableID(lockStatus.VisiblePeers, deviceID) != nil {
		// Device is a visible peer, no need to sign its node key.
		return reconcile.Result{}, nil
	}

	// Check if the operator's lock key is trusted.
	if !slices.ContainsFunc(lockStatus.TrustedKeys, func(k ipnstate.TKAKey) bool {
		return lockStatus.PublicKey.Equal(k.Key)
	}) {
		logger.Warnf("Operator key is not trusted by the network. Add %q to the trusted signer keys", lockStatus.PublicKey.CLIString())
		return reconcile.Result{RequeueAfter: requeueInterval}, nil
	}

	devicePeer := findTKAPeerByStableID(lockStatus.FilteredPeers, deviceID)
	if devicePeer == nil {
		logger.Debugf("Device %q is not found in filtered peers list, deferring signing", deviceID)
		return reconcile.Result{RequeueAfter: requeueInterval}, nil
	}

	if nodeKey != devicePeer.NodeKey {
		logger.Warnf("Device %q peer key from control (%s) does not match key in device state (%s)", deviceID, devicePeer.NodeKey.ShortString(), nodeKey.ShortString())
		// May be a lagging netmap update in the operator; requeue.
		return reconcile.Result{RequeueAfter: requeueInterval}, nil
	}

	// Lock is enabled, but the device node key is not signed yet.
	logger.Infof("Network is locked. Attempting to sign device node key with operator key %q", lockStatus.PublicKey.CLIString())

	if err := r.localClient.TailnetLockSign(ctx, nodeKey, nil); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to sign node key: %w", err)
	}

	return reconcile.Result{}, nil
}

func findTKAPeerByStableID(peers []*ipnstate.TKAPeer, deviceID tailcfg.StableNodeID) *ipnstate.TKAPeer {
	for _, p := range peers {
		if p.StableID == deviceID {
			return p
		}
	}
	return nil
}

// getDeviceKey returns the node's public key from the IPN profile that
// tailscaled stores in its state Secret. It returns a zero key if the
// profile has not been written yet.
func getDeviceKey(secret *corev1.Secret) (key.NodePublic, error) {
	currentProfile, ok := secret.Data[currentProfileKey]
	if !ok {
		return key.NodePublic{}, nil
	}
	profileBytes := secret.Data[string(currentProfile)]
	if len(profileBytes) == 0 {
		return key.NodePublic{}, nil
	}
	var prefs ipn.Prefs
	if err := json.Unmarshal(profileBytes, &prefs); err != nil {
		return key.NodePublic{}, fmt.Errorf("failed to extract node profile info from state Secret %s: %w", secret.Name, err)
	}
	if prefs.Persist == nil {
		return key.NodePublic{}, nil
	}
	nodeKey, _ := prefs.Persist.PublicNodeKeyOK()

	return nodeKey, nil
}

// managedSecretHandler filters Secret events to only those which are managed
// by the operator within the given namespace and may hold proxy state. Secrets
// labeled with a secret type other than "state" are skipped; unlabeled Secrets
// are kept, as the state Secrets of standalone proxies carry no secret type label.
func managedSecretHandler(ns string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		if o.GetNamespace() != ns {
			return nil
		}
		if !reconciler.IsManagedResource(o) {
			return nil
		}
		if t, ok := o.GetLabels()[kubetypes.LabelSecretType]; ok && t != kubetypes.LabelSecretTypeState {
			return nil
		}
		return []reconcile.Request{
			{NamespacedName: client.ObjectKeyFromObject(o)},
		}
	}
}
