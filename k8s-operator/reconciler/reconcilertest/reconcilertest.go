// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package reconcilertest provides helpers for testing the CRD reconcilers under k8s-operator/reconciler. It covers
// the parts of a reconciler test that are the same whichever CRD is under test: building a fake client with the
// operator's scheme, creating and mutating objects in it, asserting on what a reconcile left behind, and faking the
// Tailscale API.
//
// Assertions come in two flavours. Must* helpers set up test preconditions and call t.Fatalf if the cluster doesn't
// behave, because a failed precondition makes the rest of the test meaningless. Expect* helpers assert on the state
// a reconcile produced.
//
// Per-CRD assertions belong in the reconciler's own test package; only helpers that are genuinely reconciler-
// agnostic belong here.
package reconcilertest

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
)

// NewClientBuilder returns a fake client builder preconfigured with the operator's scheme. Callers add their own
// objects, status subresources and interceptors before calling Build.
func NewClientBuilder() *fake.ClientBuilder {
	return fake.NewClientBuilder().WithScheme(tsapi.GlobalScheme)
}

// ApplyPatchInterceptor returns interceptor funcs that emulate server-side apply, which the fake client does not
// implement. Apply patches become a Create if the object is absent and an Update if it is present; every other patch
// type is passed through untouched. Reconcilers that apply their children (rather than using
// reconciler.CreateOrUpdate) need this to be testable against the fake client.
func ApplyPatchInterceptor() interceptor.Funcs {
	return interceptor.Funcs{
		Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if patch.Type() != types.ApplyPatchType {
				return cl.Patch(ctx, obj, patch, opts...)
			}

			key := client.ObjectKeyFromObject(obj)
			existing := obj.DeepCopyObject().(client.Object)
			if err := cl.Get(ctx, key, existing); err != nil {
				if !apierrors.IsNotFound(err) {
					return err
				}

				return cl.Create(ctx, obj)
			}

			obj.SetResourceVersion(existing.GetResourceVersion())
			return cl.Update(ctx, obj)
		},
	}
}

// MustCreate creates obj, failing the test if the cluster rejects it.
func MustCreate(t *testing.T, c client.Client, obj client.Object) {
	t.Helper()
	if err := c.Create(t.Context(), obj); err != nil {
		t.Fatalf("creating %q: %v", obj.GetName(), err)
	}
}

// MustGet reads ns/name into obj, failing the test if it is absent. Use ExpectMissing to assert the opposite.
func MustGet(t *testing.T, c client.Client, ns, name string, obj client.Object) {
	t.Helper()
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: ns, Name: name}, obj); err != nil {
		t.Fatalf("getting %q: %v", name, err)
	}
}

// MustDeleteAll deletes each of objs in order.
func MustDeleteAll(t *testing.T, c client.Client, objs ...client.Object) {
	t.Helper()
	for _, obj := range objs {
		if err := c.Delete(t.Context(), obj); err != nil {
			t.Fatalf("deleting %q: %v", obj.GetName(), err)
		}
	}
}

// MustUpdate reads ns/name, applies update to it and writes it back. It reads the object fresh rather than taking one
// from the caller so the update is applied to the current ResourceVersion.
func MustUpdate[T any, O reconciler.PtrObject[T]](t *testing.T, c client.Client, ns, name string, update func(O)) {
	t.Helper()
	obj := O(new(T))
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: ns, Name: name}, obj); err != nil {
		t.Fatalf("getting %q: %v", name, err)
	}
	update(obj)
	if err := c.Update(t.Context(), obj); err != nil {
		t.Fatalf("updating %q: %v", name, err)
	}
}

// MustUpdateStatus is MustUpdate for the status subresource. The object's type must have been registered with
// WithStatusSubresource on the fake client builder.
func MustUpdateStatus[T any, O reconciler.PtrObject[T]](t *testing.T, c client.Client, ns, name string, update func(O)) {
	t.Helper()
	obj := O(new(T))
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: ns, Name: name}, obj); err != nil {
		t.Fatalf("getting %q: %v", name, err)
	}
	update(obj)
	if err := c.Status().Update(t.Context(), obj); err != nil {
		t.Fatalf("updating status %q: %v", name, err)
	}
}

// ExpectEqual asserts that the object named by want exists and matches it. ResourceVersion and TypeMeta are cleared
// on both sides first: the former changes on every no-op write and the latter is populated by the fake client but not
// by the callers building expected objects, so asserting on either makes tests brittle. Pass modifiers to blank out
// any further fields that shouldn't be compared; each one runs against both want and got.
func ExpectEqual[T any, O reconciler.PtrObject[T]](t *testing.T, c client.Client, want O, modifiers ...func(O)) {
	t.Helper()
	got := O(new(T))
	if err := c.Get(t.Context(), types.NamespacedName{
		Name:      want.GetName(),
		Namespace: want.GetNamespace(),
	}, got); err != nil {
		t.Fatalf("getting %q: %v", want.GetName(), err)
	}
	got.SetResourceVersion("")
	want.SetResourceVersion("")
	got.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{})
	want.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{})
	for _, modifier := range modifiers {
		modifier(want)
		modifier(got)
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected %s (-got +want):\n%s", reflect.TypeOf(want).Elem().Name(), diff)
	}
}

// ExpectMissing asserts that no object of type T exists at ns/name.
func ExpectMissing[T any, O reconciler.PtrObject[T]](t *testing.T, c client.Client, ns, name string) {
	t.Helper()
	obj := O(new(T))
	err := c.Get(t.Context(), types.NamespacedName{Namespace: ns, Name: name}, obj)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("%s %s/%s unexpectedly present, wanted missing", reflect.TypeOf(obj).Elem().Name(), ns, name)
	}
}

// ExpectReconciled runs a single reconcile for ns/name and asserts it succeeded without asking to be requeued, i.e.
// the reconciler considers the resource fully settled.
func ExpectReconciled(t *testing.T, r reconcile.Reconciler, ns, name string) {
	t.Helper()
	res, err := r.Reconcile(t.Context(), request(ns, name))
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if res.Requeue {
		t.Fatalf("unexpected immediate requeue")
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("unexpected timed requeue (%v)", res.RequeueAfter)
	}
}

func request(ns, name string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}
}

// ExpectEvents asserts that exactly the given events are emitted on rec, waiting up to five seconds for each. Events
// are not required to arrive in order, because a reconcile may emit them from more than one code path.
func ExpectEvents(t *testing.T, rec *record.FakeRecorder, want []string) {
	t.Helper()
	seen := make([]string, 0, len(want))
	for range want {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case got := <-rec.Events:
			if !slices.Contains(want, got) {
				t.Errorf("got unexpected event %q, expected events: %+#v", got, want)
				continue
			}
			seen = append(seen, got)
		case <-timer.C:
			t.Errorf("timeout waiting for an event, wants events %+#v, got events %+#v", want, seen)
		}
	}
}
