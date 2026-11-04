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
	"errors"
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

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	reconcilerName = "nodekey-reconciler"

	// requeueInterval is how often to recheck a device that can't be signed yet for reasons outside its state
	// Secret, such as an untrusted operator key or a device missing from the operator's netmap.
	// Reconciles are typically triggered by a change to the device's state Secret; this serves as a polling
	// fallback for instances where the key cannot be signed yet.
	requeueInterval = 60 * time.Second
)

var errOperatorUntrusted = errors.New("operator key is not trusted by the network")

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

	if done, err := r.signNodeKey(ctx, logger, secret); errors.Is(err, errOperatorUntrusted) {
		return reconcile.Result{RequeueAfter: requeueInterval}, nil
	} else if !done {
		return reconcile.Result{RequeueAfter: requeueInterval}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// signNodeKey signs the device node key with the operator's lock key if the
// network is locked. It does nothing if the network is not locked or if the
// device node key is already signed.
// If the device is not ready to be signed yet and should be requeued, it returns
// false. If the device is already signed, the state secret is missing
// required information, or an error occurs, it returns true.
func (r *Reconciler) signNodeKey(ctx context.Context, logger *zap.SugaredLogger, secret *corev1.Secret) (bool, error) {
	deviceID := tailcfg.StableNodeID(secret.Data[kubetypes.KeyDeviceID])
	if deviceID.IsZero() {
		logger.Debug("NodeID is empty. It may not be populated yet")
		return true, nil
	}

	lockStatus, err := r.localClient.TailnetLockStatus(ctx)
	if err != nil {
		return true, fmt.Errorf("failed to get tailnet lock status: %w", err)
	}

	if !lockStatus.Enabled {
		logger.Debugf("Tailnet is not locked, skipping node key signing")
		return true, nil
	}

	if findTKAPeerByStableID(lockStatus.VisiblePeers, deviceID) != nil {
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

	devicePeer := findTKAPeerByStableID(lockStatus.FilteredPeers, deviceID)
	if devicePeer == nil {
		logger.Debugf("Device %q is not found in filtered peers list, deferring signing", deviceID)
		return false, nil
	}

	nodeKeyEncoded := secret.Data[kubetypes.KeyNodeKey]
	if len(nodeKeyEncoded) == 0 {
		logger.Debugf("Device %q state secret does not contain the node key; waiting for update", deviceID)
		// No requeue; wait for state secret watch to trigger.
		return true, nil
	}
	var nodeKey key.NodePublic
	if err := nodeKey.UnmarshalText(nodeKeyEncoded); err != nil {
		return true, fmt.Errorf("failed to unmarshal device node key: %w", err)
	}
	if nodeKey != devicePeer.NodeKey {
		logger.Warnf("Device %q peer key from control (%s) does not match key in device state (%s)", deviceID, devicePeer.NodeKey.ShortString(), nodeKey.ShortString())
		return false, nil
	}

	// Lock is enabled, but the device node key is not signed yet.
	logger.Infof("Network is locked. Attempting to sign device node key with operator key %q", lockStatus.PublicKey.CLIString())

	if err := r.localClient.TailnetLockSign(ctx, nodeKey, nil); err != nil {
		return true, fmt.Errorf("failed to sign node key: %w", err)
	}

	return true, nil
}

func findTKAPeerByStableID(peers []*ipnstate.TKAPeer, deviceID tailcfg.StableNodeID) *ipnstate.TKAPeer {
	for _, p := range peers {
		if p.StableID == deviceID {
			return p
		}
	}
	return nil
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
