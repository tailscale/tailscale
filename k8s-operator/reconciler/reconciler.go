// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package reconciler provides utilities for working with Kubernetes resources within controller reconciliation
// loops.
package reconciler

import (
	"context"
	"slices"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/kube/kubetypes"
)

const (
	// FinalizerName is the common finalizer used across all Tailscale Kubernetes resources.
	FinalizerName = "tailscale.com/finalizer"

	// LabelParentType identifies which Tailscale CRD kind owns a managed resource. Every resource that a Tailscale
	// CRD reconciler creates should carry this label alongside LabelParentName.
	LabelParentType = "tailscale.com/parent-resource-type"

	// LabelParentName identifies the name of the Tailscale CRD that owns a managed resource. Combined with
	// LabelParentType, this uniquely identifies the parent within its scope.
	LabelParentName = "tailscale.com/parent-resource"

	// LabelParentNamespace identifies the namespace of the owning Tailscale CRD. It is only stamped when the parent
	// CRD is namespaced; cluster-scoped parents omit it.
	LabelParentNamespace = "tailscale.com/parent-resource-ns"
)

// SetFinalizer adds the finalizer to the resource if not already present.
func SetFinalizer(obj client.Object) {
	if idx := slices.Index(obj.GetFinalizers(), FinalizerName); idx >= 0 {
		return
	}

	obj.SetFinalizers(append(obj.GetFinalizers(), FinalizerName))
}

// RemoveFinalizer removes the finalizer from the resource if present.
func RemoveFinalizer(obj client.Object) {
	idx := slices.Index(obj.GetFinalizers(), FinalizerName)
	if idx < 0 {
		return
	}

	finalizers := obj.GetFinalizers()
	obj.SetFinalizers(append(finalizers[:idx], finalizers[idx+1:]...))
}

// Labels returns the standard ownership labels stamped on every resource a Tailscale CRD reconciler creates:
// tailscale.com/managed=true, plus LabelParentType and LabelParentName. If parentNamespace is non-empty (i.e. the
// parent CRD is namespaced) it is stamped as LabelParentNamespace; cluster-scoped parents pass "".
func Labels(parentType, parentName, parentNamespace string) map[string]string {
	labels := map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentType:        parentType,
		LabelParentName:        parentName,
	}
	if parentNamespace != "" {
		labels[LabelParentNamespace] = parentNamespace
	}
	return labels
}

// EnqueueForChild returns a handler.MapFunc that enqueues a reconcile.Request for the parent CRD of a managed child
// resource. It filters by tailscale.com/managed=true and LabelParentType, and derives the request's NamespacedName
// from LabelParentName plus LabelParentNamespace (blank namespace for cluster-scoped parents). Use it on Watches of
// child resources so drift or cloud-controller updates propagate to the owning CRD's reconciler.
func EnqueueForChild(parentType string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		labels := o.GetLabels()
		if labels[kubetypes.LabelManaged] != "true" || labels[LabelParentType] != parentType {
			return nil
		}

		name := labels[LabelParentName]
		if name == "" {
			return nil
		}

		return []reconcile.Request{{NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: labels[LabelParentNamespace],
		}}}
	}
}
