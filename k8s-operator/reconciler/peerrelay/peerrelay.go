// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package peerrelay provides reconciliation logic for the PeerRelay custom resource definition. It is responsible
// for managing the lifecycle of PeerRelay devices, including the StatefulSet and Service resources used to expose
// them.
package peerrelay

import (
	"context"

	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

type (
	// The Reconciler type is a reconcile.TypedReconciler implementation used to manage the reconciliation of
	// PeerRelay custom resources.
	Reconciler struct {
		client.Client

		logger *zap.SugaredLogger
	}

	// The ReconcilerOptions type contains configuration values for the Reconciler.
	ReconcilerOptions struct {
		// The client for interacting with the Kubernetes API.
		Client client.Client
		// The logger to use for this Reconciler.
		Logger *zap.SugaredLogger
	}
)

const reconcilerName = "peerrelay-reconciler"

// NewReconciler returns a new instance of the Reconciler type. It watches specifically for changes to PeerRelay
// custom resources. The ReconcilerOptions can be used to modify the behaviour of the Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	return &Reconciler{
		Client: options.Client,
		logger: options.Logger.Named(reconcilerName),
	}
}

// Register the Reconciler onto the given manager.Manager implementation.
func (r *Reconciler) Register(mgr manager.Manager) error {
	return builder.
		ControllerManagedBy(mgr).
		For(&tsapi.PeerRelay{}).
		Named(reconcilerName).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	return reconcile.Result{}, nil
}
