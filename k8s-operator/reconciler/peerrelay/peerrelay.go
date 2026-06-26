// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package peerrelay provides reconciliation logic for the PeerRelay custom resource definition. It is responsible
// for managing the lifecycle of PeerRelay devices, including the StatefulSet and Service resources used to expose
// them.
package peerrelay

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
)

type (
	// The Reconciler type is a reconcile.TypedReconciler implementation used to manage the reconciliation of
	// PeerRelay custom resources.
	Reconciler struct {
		client.Client

		tailscaleNamespace string
		logger             *zap.SugaredLogger
	}

	// The ReconcilerOptions type contains configuration values for the Reconciler.
	ReconcilerOptions struct {
		// The client for interacting with the Kubernetes API.
		Client client.Client
		// The namespace the operator is installed in. PeerRelay-managed resources (Services, StatefulSets, etc.)
		// are created within this namespace.
		TailscaleNamespace string
		// The logger to use for this Reconciler.
		Logger *zap.SugaredLogger
	}
)

const reconcilerName = "peerrelay-reconciler"

// NewReconciler returns a new instance of the Reconciler type. It watches specifically for changes to PeerRelay
// custom resources. The ReconcilerOptions can be used to modify the behaviour of the Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	return &Reconciler{
		Client:             options.Client,
		tailscaleNamespace: options.TailscaleNamespace,
		logger:             options.Logger.Named(reconcilerName),
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

// Reconcile is invoked when a change occurs to PeerRelay resources within the cluster. On create/update, it ensures
// one LoadBalancer Service exists per replica. On delete, all managed Services are removed before the finalizer is
// released.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var pr tsapi.PeerRelay
	err := r.Get(ctx, req.NamespacedName, &pr)
	switch {
	case apierrors.IsNotFound(err):
		return reconcile.Result{}, nil
	case err != nil:
		return reconcile.Result{}, fmt.Errorf("failed to get PeerRelay %q: %w", req.NamespacedName, err)
	}

	if !pr.DeletionTimestamp.IsZero() {
		return r.delete(ctx, &pr)
	}

	return r.createOrUpdate(ctx, &pr)
}

func (r *Reconciler) createOrUpdate(ctx context.Context, pr *tsapi.PeerRelay) (reconcile.Result, error) {
	reconciler.SetFinalizer(pr)
	if err := r.Update(ctx, pr); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to add finalizer to PeerRelay %q: %w", pr.Name, err)
	}

	replicas := int32(1)
	if pr.Spec.Replicas != nil {
		replicas = *pr.Spec.Replicas
	}

	for i := int32(0); i < replicas; i++ {
		desired := r.peerRelayService(pr, i)
		if err := r.ensureService(ctx, desired); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to apply Service %q: %w", desired.Name, err)
		}
	}

	if err := r.deleteServicesFrom(ctx, pr, replicas); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to clean up scaled-down Services for PeerRelay %q: %w", pr.Name, err)
	}

	return reconcile.Result{}, nil
}

func (r *Reconciler) delete(ctx context.Context, pr *tsapi.PeerRelay) (reconcile.Result, error) {
	if err := r.deleteServicesFrom(ctx, pr, 0); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete Services for PeerRelay %q: %w", pr.Name, err)
	}

	reconciler.RemoveFinalizer(pr)
	if err := r.Update(ctx, pr); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to remove finalizer from PeerRelay %q: %w", pr.Name, err)
	}

	return reconcile.Result{}, nil
}

func (r *Reconciler) ensureService(ctx context.Context, desired *corev1.Service) error {
	var existing corev1.Service
	err := r.Get(ctx, types.NamespacedName{Namespace: desired.Namespace, Name: desired.Name}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		if err = r.Create(ctx, desired); err != nil {
			return fmt.Errorf("failed to create Service: %w", err)
		}

		return nil
	case err != nil:
		return fmt.Errorf("failed to get Service: %w", err)
	}

	existing.Labels = desired.Labels
	existing.Annotations = desired.Annotations
	existing.OwnerReferences = desired.OwnerReferences
	existing.Spec.Type = desired.Spec.Type
	existing.Spec.Selector = desired.Spec.Selector
	existing.Spec.Ports = desired.Spec.Ports

	if err = r.Update(ctx, &existing); err != nil {
		return fmt.Errorf("failed to update Service: %w", err)
	}

	return nil
}

func (r *Reconciler) deleteServicesFrom(ctx context.Context, pr *tsapi.PeerRelay, fromIdx int32) error {
	var list corev1.ServiceList
	if err := r.List(ctx, &list, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(peerRelayLabels(pr.Name))); err != nil {
		return fmt.Errorf("failed to list Services: %w", err)
	}

	for i := range list.Items {
		svc := &list.Items[i]
		idx, ok := replicaIndexFromService(svc)
		if !ok || idx < fromIdx {
			continue
		}

		if err := r.Delete(ctx, svc); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete Service %q: %w", svc.Name, err)
		}
	}

	return nil
}
