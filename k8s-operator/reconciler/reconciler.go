// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package reconciler provides utilities for working with Kubernetes resources within controller reconciliation
// loops.
package reconciler

import (
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// FinalizerName is the common finalizer used across all Tailscale Kubernetes resources.
	FinalizerName = "tailscale.com/finalizer"
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
