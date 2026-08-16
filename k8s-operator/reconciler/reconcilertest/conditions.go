// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package reconcilertest

import (
	"testing"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

// The condition helpers below take a []metav1.Condition rather than the owning object. Every Tailscale CRD stores its
// conditions in Status.Conditions, but the CRD types live in tsapi and so can't grow a shared accessor method from
// here; taking the slice keeps these usable from every reconciler's tests (and for corev1.Service conditions) without
// per-CRD plumbing. Pair them with MustGet:
//
//	tsr := &tsapi.Recorder{}
//	reconcilertest.MustGet(t, fc, "", "test", tsr)
//	reconcilertest.ExpectCondition(t, tsr.Status.Conditions, tsapi.RecorderReady, metav1.ConditionTrue, reason, message)

// Condition returns the condition of the given type, failing the test if it isn't present. Use it when a test needs to
// inspect a condition's fields directly, e.g. to match part of a message generated outside this repo; prefer
// ExpectCondition for whole-condition assertions.
func Condition(t *testing.T, conds []metav1.Condition, conditionType tsapi.ConditionType) metav1.Condition {
	t.Helper()
	cond := apimeta.FindStatusCondition(conds, string(conditionType))
	if cond == nil {
		t.Fatalf("no %s condition found, got %+v", conditionType, conds)
	}
	return *cond
}

// ExpectCondition asserts that a condition of the given type is present with the given status, reason and message.
// LastTransitionTime and ObservedGeneration are not compared, so tests don't need a fixed clock or to track
// generations in order to assert on the parts that describe the outcome.
func ExpectCondition(t *testing.T, conds []metav1.Condition, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string) {
	t.Helper()
	got := Condition(t, conds, conditionType)
	if got.Status != status || got.Reason != reason || got.Message != message {
		t.Fatalf("unexpected %s condition: got (%s, %s, %q), want (%s, %s, %q)",
			conditionType, got.Status, got.Reason, got.Message, status, reason, message)
	}
}

// ExpectConditionStatus asserts a condition's status and reason, ignoring its message. Use it when the message is
// long, generated outside this repo, or otherwise not the point of the test.
func ExpectConditionStatus(t *testing.T, conds []metav1.Condition, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason string) {
	t.Helper()
	got := Condition(t, conds, conditionType)
	if got.Status != status || got.Reason != reason {
		t.Fatalf("unexpected %s condition: got (%s, %s), want (%s, %s)",
			conditionType, got.Status, got.Reason, status, reason)
	}
}
