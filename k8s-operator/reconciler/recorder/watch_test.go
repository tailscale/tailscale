// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package recorder

import (
	"testing"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/reconcilertest"
)

func TestRecordersForTailnet(t *testing.T) {
	recorders := []client.Object{
		&tsapi.Recorder{ObjectMeta: metav1.ObjectMeta{Name: "on-a"}, Spec: tsapi.RecorderSpec{Tailnet: "a"}},
		&tsapi.Recorder{ObjectMeta: metav1.ObjectMeta{Name: "on-b"}, Spec: tsapi.RecorderSpec{Tailnet: "b"}},
		&tsapi.Recorder{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
	}
	r := &Reconciler{
		Client: reconcilertest.NewClientBuilder().WithObjects(recorders...).Build(),
		logger: zap.NewNop().Sugar(),
	}

	reqs := r.recordersForTailnet(t.Context(), &tsapi.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "a"}})
	if len(reqs) != 1 || reqs[0].Name != "on-a" {
		t.Fatalf("recordersForTailnet(a) = %v, want only on-a", reqs)
	}
	if reqs := r.recordersForTailnet(t.Context(), &tsapi.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "none"}}); len(reqs) != 0 {
		t.Fatalf("recordersForTailnet(none) = %v, want none", reqs)
	}
}
