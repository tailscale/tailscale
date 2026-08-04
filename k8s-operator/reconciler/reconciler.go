// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package reconciler provides utilities for working with Kubernetes resources within controller reconciliation
// loops.
package reconciler

import (
	"context"
	"fmt"
	"slices"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/kube/kubetypes"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

const (
	// Finalizer is the common finalizer used across all Tailscale Kubernetes resources.
	Finalizer = "tailscale.com/finalizer"

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

// SetFinalizer adds name to obj's finalizers if not already present. Most CRD reconcilers pass Finalizer; per-
// reconciler names are used when a single resource may carry finalizers from multiple reconcilers that each need to run
// their own cleanup.
func SetFinalizer(obj client.Object, name string) {
	if idx := slices.Index(obj.GetFinalizers(), name); idx >= 0 {
		return
	}

	obj.SetFinalizers(append(obj.GetFinalizers(), name))
}

// RemoveFinalizer removes name from obj's finalizers if present.
func RemoveFinalizer(obj client.Object, name string) {
	idx := slices.Index(obj.GetFinalizers(), name)
	if idx < 0 {
		return
	}

	finalizers := obj.GetFinalizers()
	obj.SetFinalizers(append(finalizers[:idx], finalizers[idx+1:]...))
}

// EnsureFinalizer adds name to obj (if not already present) and persists the change via cl.Update. It is a no-op when
// the finalizer is already set. Callers should invoke it early in a create/update reconcile so cleanup logic gets a
// chance to run before the resource is garbage collected. Most callers pass Finalizer; per-reconciler names are
// used when a single resource may carry finalizers from multiple reconcilers.
func EnsureFinalizer(ctx context.Context, cl client.Client, obj client.Object, name string) error {
	if slices.Contains(obj.GetFinalizers(), name) {
		return nil
	}
	SetFinalizer(obj, name)
	return cl.Update(ctx, obj)
}

// ClearFinalizer removes name from obj (if present) and persists the change via cl.Update. It is a no-op when the
// finalizer is already absent. Callers should invoke it at the end of delete handling, once all owned resources are
// gone, so the API server can garbage collect obj.
func ClearFinalizer(ctx context.Context, cl client.Client, obj client.Object, name string) error {
	if !slices.Contains(obj.GetFinalizers(), name) {
		return nil
	}
	RemoveFinalizer(obj, name)
	return cl.Update(ctx, obj)
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
		if !IsManagedByType(o, parentType) {
			return nil
		}

		parent := ParentFromObjectLabels(o)
		if parent.Name == "" {
			return nil
		}

		return []reconcile.Request{{NamespacedName: parent}}
	}
}

// IsManagedResource reports whether obj carries the tailscale.com/managed=true label — i.e. it is a child resource
// stamped by a Tailscale CRD reconciler.
func IsManagedResource(obj client.Object) bool {
	return obj.GetLabels()[kubetypes.LabelManaged] == "true"
}

// IsManagedByType reports whether obj is a managed child resource whose LabelParentType matches parentType.
func IsManagedByType(obj client.Object, parentType string) bool {
	return IsManagedResource(obj) && obj.GetLabels()[LabelParentType] == parentType
}

// SelectorForType returns the label selector that matches every managed child resource with the given parent type.
// Pass it to client.MatchingLabels when Listing children by type; it is the label-map counterpart of the IsManagedByType
// predicate.
func SelectorForType(parentType string) map[string]string {
	return map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentType:        parentType,
	}
}

// ParentFromObjectLabels returns the NamespacedName of the parent CRD encoded in obj's LabelParentName /
// LabelParentNamespace labels. The Namespace is empty for children of cluster-scoped parents.
func ParentFromObjectLabels(obj client.Object) types.NamespacedName {
	labels := obj.GetLabels()
	return types.NamespacedName{
		Name:      labels[LabelParentName],
		Namespace: labels[LabelParentNamespace],
	}
}

// ResourceTracker tracks the set of CRD UIDs a reconciler currently manages and mirrors the set's size to a
// clientmetric gauge. Callers Add on each successful reconcile and Remove on cleanup; the gauge stays in sync with
// the finalizer lifecycle so it reflects the live count of managed resources across restarts. ResourceTracker is
// safe for concurrent use.
type ResourceTracker struct {
	gauge *clientmetric.Metric

	mu   sync.Mutex // protects uids
	uids set.Slice[types.UID]
}

// NewResourceTracker returns a ResourceTracker that mirrors its size to the given gauge.
func NewResourceTracker(gauge *clientmetric.Metric) *ResourceTracker {
	return &ResourceTracker{gauge: gauge}
}

// Add records uid as managed. Duplicate adds are a no-op.
func (t *ResourceTracker) Add(uid types.UID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.uids.Contains(uid) {
		return
	}
	t.uids.Add(uid)
	t.gauge.Set(int64(t.uids.Len()))
}

// Remove drops uid from the tracked set. It is a no-op if uid is not currently tracked.
func (t *ResourceTracker) Remove(uid types.UID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.uids.Remove(uid)
	t.gauge.Set(int64(t.uids.Len()))
}

// Len returns the number of UIDs currently tracked.
func (t *ResourceTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.uids.Len()
}

// PtrObject is a type constraint for pointer types that implement client.Object.
type PtrObject[T any] interface {
	client.Object
	*T
}

// CreateOrMaybeUpdate adds obj to the k8s cluster, unless the object already exists,
// in which case update is called to make changes to it. If update is nil or returns
// an error, the object is returned unmodified.
//
// obj is looked up by its Name and Namespace if Name is set, otherwise it's
// looked up by labels.
func CreateOrMaybeUpdate[T any, O PtrObject[T]](ctx context.Context, c client.Client, ns string, obj O, update func(O) error) (O, error) {
	var (
		existing O
		err      error
	)
	if obj.GetName() != "" {
		existing = new(T)
		existing.SetName(obj.GetName())
		existing.SetNamespace(obj.GetNamespace())
		err = c.Get(ctx, client.ObjectKeyFromObject(obj), existing)
	} else {
		existing, err = GetSingleObject[T, O](ctx, c, ns, obj.GetLabels())
	}
	if err == nil && existing != nil {
		if update != nil {
			if err := update(existing); err != nil {
				return nil, err
			}
			if err := c.Update(ctx, existing); err != nil {
				return nil, err
			}
		}
		return existing, nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	if err := c.Create(ctx, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// CreateOrUpdate adds obj to the k8s cluster, unless the object already exists,
// in which case update is called to make changes to it. If update is nil, the
// existing object is returned unmodified.
//
// obj is looked up by its Name and Namespace if Name is set, otherwise it's
// looked up by labels.
func CreateOrUpdate[T any, O PtrObject[T]](ctx context.Context, c client.Client, ns string, obj O, update func(O)) (O, error) {
	return CreateOrMaybeUpdate(ctx, c, ns, obj, func(o O) error {
		if update != nil {
			update(o)
		}
		return nil
	})
}

// GetSingleObject searches for k8s objects of type T (e.g. corev1.Service) with
// the given labels, and returns it. Returns nil if no objects match the labels,
// and an error if more than one object matches.
func GetSingleObject[T any, O PtrObject[T]](ctx context.Context, c client.Client, ns string, labels map[string]string) (O, error) {
	ret := O(new(T))
	kinds, _, err := c.Scheme().ObjectKinds(ret)
	if err != nil {
		return nil, err
	}
	if len(kinds) != 1 {
		// TODO: the runtime package apparently has a "pick the best
		// GVK" function somewhere that might be good enough?
		return nil, fmt.Errorf("more than 1 GroupVersionKind for %T", ret)
	}

	gvk := kinds[0]
	gvk.Kind += "List"
	lst := unstructured.UnstructuredList{}
	lst.SetGroupVersionKind(gvk)
	if err := c.List(ctx, &lst, client.InNamespace(ns), client.MatchingLabels(labels)); err != nil {
		return nil, err
	}

	if len(lst.Items) == 0 {
		return nil, nil
	}
	if len(lst.Items) > 1 {
		return nil, fmt.Errorf("found multiple matching %T objects", ret)
	}
	if err := c.Scheme().Convert(&lst.Items[0], ret, nil); err != nil {
		return nil, err
	}
	return ret, nil
}
