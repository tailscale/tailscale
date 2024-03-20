// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet.
package main

import (
	"testing"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

func TestProxyClass(t *testing.T) {
	pc := &tsapi.ProxyClass{
		TypeMeta: metav1.TypeMeta{Kind: "ProxyClass", APIVersion: "tailscale.com/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
		},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Labels:      map[string]string{"foo": "bar", "xyz1234": "abc567"},
				Annotations: map[string]string{"foo.io/bar": "{'key': 'val1232'}"},
				Pod: &tsapi.Pod{
					Labels:      map[string]string{"foo": "bar", "xyz1234": "abc567"},
					Annotations: map[string]string{"foo.io/bar": "{'key': 'val1232'}"},
				},
			},
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc).
		WithStatusSubresource(pc).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	pcr := &ProxyClassReconciler{
		Client:   fc,
		logger:   zl.Sugar(),
		clock:    cl,
		recorder: record.NewFakeRecorder(1),
	}
	expectReconciled(t, pcr, "", "test")

	// 1. A valid ProxyClass resource gets its status updated to Ready.
	pc.Status.Conditions = append(pc.Status.Conditions, tsapi.ConnectorCondition{
		Type:               tsapi.ProxyClassready,
		Status:             metav1.ConditionTrue,
		Reason:             reasonProxyClassValid,
		Message:            reasonProxyClassValid,
		LastTransitionTime: &metav1.Time{Time: cl.Now().Truncate(time.Second)},
	})

	expectEqual(t, fc, pc, nil)

	// 2. An invalid ProxyClass resource gets its status updated to Invalid.
	pc.Spec.StatefulSet.Labels["foo"] = "?!someVal"
	mustUpdate(t, fc, "", "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Labels = pc.Spec.StatefulSet.Labels
	})
	expectReconciled(t, pcr, "", "test")
	msg := `ProxyClass is not valid: .spec.statefulSet.labels: Invalid value: "?!someVal": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')`
	tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassready, metav1.ConditionFalse, reasonProxyClassInvalid, msg, 0, cl, zl.Sugar())
	expectEqual(t, fc, pc, nil)
}
