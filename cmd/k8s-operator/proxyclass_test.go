// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet.
package main

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
			UID:        types.UID("1234-UID"),
			Finalizers: []string{"tailscale.com/finalizer"},
		},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Labels:      map[string]string{"foo": "bar", "xyz1234": "abc567"},
				Annotations: map[string]string{"foo.io/bar": "{'key': 'val1232'}"},
				Pod: &tsapi.Pod{
					Labels:      map[string]string{"foo": "bar", "xyz1234": "abc567"},
					Annotations: map[string]string{"foo.io/bar": "{'key': 'val1232'}"},
					TailscaleContainer: &tsapi.Container{
						Env:             []tsapi.Env{{Name: "FOO", Value: "BAR"}},
						ImagePullPolicy: "IfNotPresent",
						Image:           "ghcr.my-repo/tailscale:v0.01testsomething",
					},
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
	fr := record.NewFakeRecorder(3) // bump this if you expect a test case to throw more events
	cl := tstest.NewClock(tstest.ClockOpts{})
	pcr := &ProxyClassReconciler{
		Client:   fc,
		logger:   zl.Sugar(),
		clock:    cl,
		recorder: fr,
	}

	// 1. A valid ProxyClass resource gets its status updated to Ready.
	expectReconciled(t, pcr, "", "test")
	pc.Status.Conditions = append(pc.Status.Conditions, metav1.Condition{
		Type:               string(tsapi.ProxyClassReady),
		Status:             metav1.ConditionTrue,
		Reason:             reasonProxyClassValid,
		Message:            reasonProxyClassValid,
		LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
	})

	expectEqual(t, fc, pc, nil)

	// 2. A ProxyClass resource with invalid labels gets its status updated to Invalid with an error message.
	pc.Spec.StatefulSet.Labels["foo"] = "?!someVal"
	mustUpdate(t, fc, "", "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Labels = pc.Spec.StatefulSet.Labels
	})
	expectReconciled(t, pcr, "", "test")
	msg := `ProxyClass is not valid: .spec.statefulSet.labels: Invalid value: "?!someVal": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')`
	tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassReady, metav1.ConditionFalse, reasonProxyClassInvalid, msg, 0, cl, zl.Sugar())
	expectEqual(t, fc, pc, nil)
	expectedEvent := "Warning ProxyClassInvalid ProxyClass is not valid: .spec.statefulSet.labels: Invalid value: \"?!someVal\": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')"
	expectEvents(t, fr, []string{expectedEvent})

	// 3. A ProxyClass resource with invalid image reference gets it status updated to Invalid with an error message.
	pc.Spec.StatefulSet.Labels = nil
	pc.Spec.StatefulSet.Pod.TailscaleContainer.Image = "FOO bar"
	mustUpdate(t, fc, "", "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Labels = nil
		proxyClass.Spec.StatefulSet.Pod.TailscaleContainer.Image = pc.Spec.StatefulSet.Pod.TailscaleContainer.Image
	})
	expectReconciled(t, pcr, "", "test")
	msg = `ProxyClass is not valid: spec.statefulSet.pod.tailscaleContainer.image: Invalid value: "FOO bar": invalid reference format: repository name (library/FOO bar) must be lowercase`
	tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassReady, metav1.ConditionFalse, reasonProxyClassInvalid, msg, 0, cl, zl.Sugar())
	expectEqual(t, fc, pc, nil)
	expectedEvent = `Warning ProxyClassInvalid ProxyClass is not valid: spec.statefulSet.pod.tailscaleContainer.image: Invalid value: "FOO bar": invalid reference format: repository name (library/FOO bar) must be lowercase`
	expectEvents(t, fr, []string{expectedEvent})

	// 4. A ProxyClass resource with invalid init container image reference gets it status updated to Invalid with an error message.
	pc.Spec.StatefulSet.Labels = nil
	pc.Spec.StatefulSet.Pod.TailscaleContainer.Image = ""
	pc.Spec.StatefulSet.Pod.TailscaleInitContainer = &tsapi.Container{
		Image: "FOO bar",
	}
	mustUpdate(t, fc, "", "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Pod.TailscaleContainer.Image = pc.Spec.StatefulSet.Pod.TailscaleContainer.Image
		proxyClass.Spec.StatefulSet.Pod.TailscaleInitContainer = &tsapi.Container{
			Image: pc.Spec.StatefulSet.Pod.TailscaleInitContainer.Image,
		}
	})
	expectReconciled(t, pcr, "", "test")
	msg = `ProxyClass is not valid: spec.statefulSet.pod.tailscaleInitContainer.image: Invalid value: "FOO bar": invalid reference format: repository name (library/FOO bar) must be lowercase`
	tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassReady, metav1.ConditionFalse, reasonProxyClassInvalid, msg, 0, cl, zl.Sugar())
	expectEqual(t, fc, pc, nil)
	expectedEvent = `Warning ProxyClassInvalid ProxyClass is not valid: spec.statefulSet.pod.tailscaleInitContainer.image: Invalid value: "FOO bar": invalid reference format: repository name (library/FOO bar) must be lowercase`
	expectEvents(t, fr, []string{expectedEvent})

	// 5. An valid ProxyClass but with a Tailscale env vars set results in warning events.
	pc.Spec.StatefulSet.Pod.TailscaleInitContainer.Image = "" // unset previous test
	mustUpdate(t, fc, "", "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Pod.TailscaleInitContainer.Image = pc.Spec.StatefulSet.Pod.TailscaleInitContainer.Image
		proxyClass.Spec.StatefulSet.Pod.TailscaleContainer.Env = []tsapi.Env{{Name: "TS_USERSPACE", Value: "true"}, {Name: "EXPERIMENTAL_TS_CONFIGFILE_PATH"}, {Name: "EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS"}}
	})
	expectedEvents := []string{"Warning CustomTSEnvVar ProxyClass overrides the default value for TS_USERSPACE env var for tailscale container. Running with custom values for Tailscale env vars is not recommended and might break in the future.",
		"Warning CustomTSEnvVar ProxyClass overrides the default value for EXPERIMENTAL_TS_CONFIGFILE_PATH env var for tailscale container. Running with custom values for Tailscale env vars is not recommended and might break in the future.",
		"Warning CustomTSEnvVar ProxyClass overrides the default value for EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS env var for tailscale container. Running with custom values for Tailscale env vars is not recommended and might break in the future."}
	expectReconciled(t, pcr, "", "test")
	expectEvents(t, fr, expectedEvents)

	// 6. A ProxyClass with ServiceMonitor enabled and in a cluster that has not ServiceMonitor CRD is invalid
	pc.Spec.Metrics = &tsapi.Metrics{Enable: true, ServiceMonitor: &tsapi.ServiceMonitor{Enable: true}}
	mustUpdate(t, fc, "", "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec = pc.Spec
	})
	expectReconciled(t, pcr, "", "test")
	msg = `ProxyClass is not valid: spec.metrics.serviceMonitor: Invalid value: "enable": ProxyClass defines that a ServiceMonitor custom resource should be created, but "servicemonitors.monitoring.coreos.com" CRD was not found`
	tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassReady, metav1.ConditionFalse, reasonProxyClassInvalid, msg, 0, cl, zl.Sugar())
	expectEqual(t, fc, pc, nil)
	expectedEvent = "Warning ProxyClassInvalid " + msg
	expectEvents(t, fr, []string{expectedEvent})

	// 7. A ProxyClass with ServiceMonitor enabled and in a cluster that does have the ServiceMonitor CRD is valid
	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: serviceMonitorCRD}}
	mustCreate(t, fc, crd)
	expectReconciled(t, pcr, "", "test")
	tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassReady, metav1.ConditionTrue, reasonProxyClassValid, reasonProxyClassValid, 0, cl, zl.Sugar())
	expectEqual(t, fc, pc, nil)
}

func TestValidateProxyClass(t *testing.T) {
	for name, tc := range map[string]struct {
		pc    *tsapi.ProxyClass
		valid bool
	}{
		"empty": {
			valid: true,
			pc:    &tsapi.ProxyClass{},
		},
		"debug_enabled_for_main_container": {
			valid: true,
			pc: &tsapi.ProxyClass{
				Spec: tsapi.ProxyClassSpec{
					StatefulSet: &tsapi.StatefulSet{
						Pod: &tsapi.Pod{
							TailscaleContainer: &tsapi.Container{
								Debug: &tsapi.Debug{
									Enable: true,
								},
							},
						},
					},
				},
			},
		},
		"debug_enabled_for_init_container": {
			valid: false,
			pc: &tsapi.ProxyClass{
				Spec: tsapi.ProxyClassSpec{
					StatefulSet: &tsapi.StatefulSet{
						Pod: &tsapi.Pod{
							TailscaleInitContainer: &tsapi.Container{
								Debug: &tsapi.Debug{
									Enable: true,
								},
							},
						},
					},
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			pcr := &ProxyClassReconciler{}
			err := pcr.validate(context.Background(), tc.pc)
			valid := err == nil
			if valid != tc.valid {
				t.Errorf("expected valid=%v, got valid=%v, err=%v", tc.valid, valid, err)
			}
		})
	}
}
