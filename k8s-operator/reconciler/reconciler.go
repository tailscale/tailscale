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

	// Label constants for tracking parent resource relationships on child resources.
	LabelParentType      = "tailscale.com/parent-resource-type"
	LabelParentName      = "tailscale.com/parent-resource"
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

// ChildResourceLabels returns labels applied to child resources created for a given parent resource.
func ChildResourceLabels(name, ns, typ string) map[string]string {
	return map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentName:        name,
		LabelParentNamespace:   ns,
		LabelParentType:        typ,
	}
}

// IsManagedResource reports whether the object is managed by the Tailscale operator.
func IsManagedResource(o client.Object) bool {
	return o.GetLabels()[kubetypes.LabelManaged] == "true"
}

// IsManagedByType reports whether the object is a managed child resource of the given parent type.
func IsManagedByType(o client.Object, typ string) bool {
	return IsManagedResource(o) && o.GetLabels()[LabelParentType] == typ
}

// ParentFromObjectLabels returns the namespaced name of the parent resource encoded in the object's labels.
func ParentFromObjectLabels(o client.Object) types.NamespacedName {
	ls := o.GetLabels()
	return types.NamespacedName{
		Namespace: ls[LabelParentNamespace],
		Name:      ls[LabelParentName],
	}
}

// ManagedResourceHandlerForType returns a handler.MapFunc that enqueues the
// parent resource for any managed child object of the given type.
func ManagedResourceHandlerForType(typ string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		if !IsManagedByType(o, typ) {
			return nil
		}
		return []reconcile.Request{
			{NamespacedName: ParentFromObjectLabels(o)},
		}
	}
}
