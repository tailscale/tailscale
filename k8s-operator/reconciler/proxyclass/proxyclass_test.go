// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package proxyclass_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/proxyclass"
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
				Labels:      tsapi.Labels{"foo": "bar", "xyz1234": "abc567"},
				Annotations: map[string]string{"foo.io/bar": "{'key': 'val1232'}"},
				Pod: &tsapi.Pod{
					Labels:      tsapi.Labels{"foo": "bar", "xyz1234": "abc567"},
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
	pcr := proxyclass.NewReconciler(proxyclass.ReconcilerOptions{
		Client:   fc,
		Recorder: fr,
		Logger:   zl.Sugar(),
		Clock:    cl,
	})

	mustReconcile := func(t *testing.T, name string) {
		t.Helper()
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: name}}
		if _, err := pcr.Reconcile(context.Background(), req); err != nil {
			t.Fatalf("Reconcile(%q): %v", name, err)
		}
	}

	mustUpdate := func(t *testing.T, name string, update func(*tsapi.ProxyClass)) {
		t.Helper()
		obj := new(tsapi.ProxyClass)
		if err := fc.Get(context.Background(), types.NamespacedName{Name: name}, obj); err != nil {
			t.Fatalf("Get(%q): %v", name, err)
		}
		update(obj)
		if err := fc.Update(context.Background(), obj); err != nil {
			t.Fatalf("Update(%q): %v", name, err)
		}
	}

	mustCreate := func(t *testing.T, obj *apiextensionsv1.CustomResourceDefinition) {
		t.Helper()
		if err := fc.Create(context.Background(), obj); err != nil {
			t.Fatalf("Create(%q): %v", obj.Name, err)
		}
	}

	expectEvents := func(t *testing.T, wantEvents []string) {
		t.Helper()
		for _, want := range wantEvents {
			timer := time.NewTimer(5 * time.Second)
			select {
			case got := <-fr.Events:
				timer.Stop()
				if got != want {
					t.Errorf("unexpected event\n got: %s\nwant: %s", got, want)
				}
			case <-timer.C:
				t.Errorf("timed out waiting for event %q", want)
			}
		}
	}

	expectStatus := func(t *testing.T, wantStatus metav1.ConditionStatus, wantReason, wantMsg string) {
		t.Helper()
		got := new(tsapi.ProxyClass)
		if err := fc.Get(context.Background(), types.NamespacedName{Name: "test"}, got); err != nil {
			t.Fatalf("Get: %v", err)
		}
		var cond *metav1.Condition
		for i := range got.Status.Conditions {
			if got.Status.Conditions[i].Type == string(tsapi.ProxyClassReady) {
				cond = &got.Status.Conditions[i]
				break
			}
		}
		if cond == nil {
			t.Fatalf("ProxyClassReady condition not set")
		}
		if cond.Status != wantStatus {
			t.Errorf("condition Status: got %q, want %q", cond.Status, wantStatus)
		}
		if cond.Reason != wantReason {
			t.Errorf("condition Reason: got %q, want %q", cond.Reason, wantReason)
		}
		if cond.Message != wantMsg {
			t.Errorf("condition Message: got %q, want %q", cond.Message, wantMsg)
		}
	}

	// 1. A valid ProxyClass resource gets its status updated to Ready.
	mustReconcile(t, "test")
	expectStatus(t, metav1.ConditionTrue, proxyclass.ReasonProxyClassValid, proxyclass.ReasonProxyClassValid)

	// 2. A ProxyClass resource with invalid labels gets its status updated to Invalid with an error message.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Labels = tsapi.Labels{"foo": "?!someVal"}
	})
	mustReconcile(t, "test")
	wantMsg := `ProxyClass is not valid: .spec.statefulSet.labels: Invalid value: "?!someVal": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')`
	expectStatus(t, metav1.ConditionFalse, proxyclass.ReasonProxyClassInvalid, wantMsg)
	expectEvents(t, []string{"Warning ProxyClassInvalid " + wantMsg})

	// 3. A ProxyClass resource with invalid image reference gets its status updated to Invalid with an error message.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Labels = nil
		proxyClass.Spec.StatefulSet.Pod.TailscaleContainer.Image = "FOO bar"
	})
	mustReconcile(t, "test")
	wantMsg = `ProxyClass is not valid: spec.statefulSet.pod.tailscaleContainer.image: Invalid value: "FOO bar": invalid reference format: repository name (library/FOO bar) must be lowercase`
	expectStatus(t, metav1.ConditionFalse, proxyclass.ReasonProxyClassInvalid, wantMsg)
	expectEvents(t, []string{"Warning ProxyClassInvalid " + wantMsg})

	// 4. A ProxyClass resource with invalid init container image reference gets its status updated to Invalid with an error message.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Pod.TailscaleContainer.Image = ""
		proxyClass.Spec.StatefulSet.Pod.TailscaleInitContainer = &tsapi.Container{Image: "FOO bar"}
	})
	mustReconcile(t, "test")
	wantMsg = `ProxyClass is not valid: spec.statefulSet.pod.tailscaleInitContainer.image: Invalid value: "FOO bar": invalid reference format: repository name (library/FOO bar) must be lowercase`
	expectStatus(t, metav1.ConditionFalse, proxyclass.ReasonProxyClassInvalid, wantMsg)
	expectEvents(t, []string{"Warning ProxyClassInvalid " + wantMsg})

	// 5. A valid ProxyClass but with Tailscale env vars set results in warning events.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Pod.TailscaleInitContainer.Image = ""
		proxyClass.Spec.StatefulSet.Pod.TailscaleContainer.Env = []tsapi.Env{
			{Name: "TS_USERSPACE", Value: "true"},
			{Name: "EXPERIMENTAL_TS_CONFIGFILE_PATH"},
			{Name: "EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS"},
		}
	})
	mustReconcile(t, "test")
	expectEvents(t, []string{
		"Warning CustomTSEnvVar ProxyClass overrides the default value for TS_USERSPACE env var for tailscale container. Running with custom values for Tailscale env vars is not recommended and might break in the future.",
		"Warning CustomTSEnvVar ProxyClass overrides the default value for EXPERIMENTAL_TS_CONFIGFILE_PATH env var for tailscale container. Running with custom values for Tailscale env vars is not recommended and might break in the future.",
		"Warning CustomTSEnvVar ProxyClass overrides the default value for EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS env var for tailscale container. Running with custom values for Tailscale env vars is not recommended and might break in the future.",
	})

	// 6. A ProxyClass with ServiceMonitor enabled in a cluster without the ServiceMonitor CRD is invalid.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Pod.TailscaleContainer.Env = nil // clear TS_ env vars from step 5
		proxyClass.Spec.Metrics = &tsapi.Metrics{Enable: true, ServiceMonitor: &tsapi.ServiceMonitor{Enable: true}}
	})
	mustReconcile(t, "test")
	wantMsg = `ProxyClass is not valid: spec.metrics.serviceMonitor: Invalid value: "enable": ProxyClass defines that a ServiceMonitor custom resource should be created, but "servicemonitors.monitoring.coreos.com" CRD was not found`
	expectStatus(t, metav1.ConditionFalse, proxyclass.ReasonProxyClassInvalid, wantMsg)
	expectEvents(t, []string{"Warning ProxyClassInvalid " + wantMsg})

	// 7. A ProxyClass with ServiceMonitor enabled in a cluster that has the ServiceMonitor CRD is valid.
	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: proxyclass.ServiceMonitorCRD}}
	mustCreate(t, crd)
	mustReconcile(t, "test")
	expectStatus(t, metav1.ConditionTrue, proxyclass.ReasonProxyClassValid, proxyclass.ReasonProxyClassValid)

	// 8. A ProxyClass with invalid ServiceMonitor labels gets its status updated to Invalid with an error message.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.Metrics.ServiceMonitor.Labels = tsapi.Labels{"foo": "bar!"}
	})
	mustReconcile(t, "test")
	wantMsg = `ProxyClass is not valid: .spec.metrics.serviceMonitor.labels: Invalid value: "bar!": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')`
	expectStatus(t, metav1.ConditionFalse, proxyclass.ReasonProxyClassInvalid, wantMsg)

	// 9. A ProxyClass with valid ServiceMonitor labels gets its status updated to Valid.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.Metrics.ServiceMonitor.Labels = tsapi.Labels{"foo": "bar", "xyz1234": "abc567", "empty": "", "onechar": "a"}
	})
	mustReconcile(t, "test")
	expectStatus(t, metav1.ConditionTrue, proxyclass.ReasonProxyClassValid, proxyclass.ReasonProxyClassValid)
}

func TestProxyClassValidation(t *testing.T) {
	// Existing ready ProxyClass used by clash-detection cases. Its NodePort ports occupy 31000 and 32000, so any
	// candidate range that spans them is rejected.
	cl := tstest.NewClock(tstest.ClockOpts{})
	existingPC := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-pc"},
		Spec: tsapi.ProxyClassSpec{
			StaticEndpoints: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{
					Ports:    []tsapi.PortRange{{Port: 31000}, {Port: 32000}},
					Selector: map[string]string{"foo/bar": "baz"},
				},
			},
		},
		Status: tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Type:               string(tsapi.ProxyClassReady),
				Status:             metav1.ConditionTrue,
				Reason:             proxyclass.ReasonProxyClassValid,
				Message:            proxyclass.ReasonProxyClassValid,
				LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
			}},
		},
	}

	nodePortWith := func(ports []tsapi.PortRange) *tsapi.StaticEndpointsConfig {
		return &tsapi.StaticEndpointsConfig{
			NodePort: &tsapi.NodePortConfig{
				Ports:    ports,
				Selector: map[string]string{"kubernetes.io/hostname": "foobar"},
			},
		}
	}

	for name, tc := range map[string]struct {
		spec         tsapi.ProxyClassSpec
		seedExisting bool
		valid        bool
	}{
		"empty": {
			spec:  tsapi.ProxyClassSpec{},
			valid: true,
		},
		"debug_enabled_for_main_container": {
			spec: tsapi.ProxyClassSpec{
				StatefulSet: &tsapi.StatefulSet{
					Pod: &tsapi.Pod{
						TailscaleContainer: &tsapi.Container{Debug: &tsapi.Debug{Enable: true}},
					},
				},
			},
			valid: true,
		},
		"debug_enabled_for_init_container": {
			spec: tsapi.ProxyClassSpec{
				StatefulSet: &tsapi.StatefulSet{
					Pod: &tsapi.Pod{
						TailscaleInitContainer: &tsapi.Container{Debug: &tsapi.Debug{Enable: true}},
					},
				},
			},
			valid: false,
		},
		"static_endpoints_valid_specific_ports": {
			spec:  tsapi.ProxyClassSpec{StaticEndpoints: nodePortWith([]tsapi.PortRange{{Port: 3001}, {Port: 3005}})},
			valid: true,
		},
		"static_endpoints_valid_port_ranges": {
			spec:  tsapi.ProxyClassSpec{StaticEndpoints: nodePortWith([]tsapi.PortRange{{Port: 3000, EndPort: 3002}, {Port: 3005, EndPort: 3007}})},
			valid: true,
		},
		"static_endpoints_overlapping_port_ranges": {
			spec:  tsapi.ProxyClassSpec{StaticEndpoints: nodePortWith([]tsapi.PortRange{{Port: 1000, EndPort: 2000}, {Port: 1500, EndPort: 1800}})},
			valid: false,
		},
		"static_endpoints_clashing_port_and_range": {
			spec:  tsapi.ProxyClassSpec{StaticEndpoints: nodePortWith([]tsapi.PortRange{{Port: 3005}, {Port: 3001, EndPort: 3010}})},
			valid: false,
		},
		"static_endpoints_malformed_port_range": {
			spec:  tsapi.ProxyClassSpec{StaticEndpoints: nodePortWith([]tsapi.PortRange{{Port: 3001, EndPort: 3000}})},
			valid: false,
		},
		"static_endpoints_empty_selector": {
			spec: tsapi.ProxyClassSpec{StaticEndpoints: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{Ports: []tsapi.PortRange{{Port: 3000}}, Selector: map[string]string{}},
			}},
			valid: true,
		},
		"nodeport_ranges_adjacent_no_overlap": {
			spec:         tsapi.ProxyClassSpec{StaticEndpoints: nodePortWith([]tsapi.PortRange{{Port: 30010, EndPort: 30020}, {Port: 30021, EndPort: 30022}})},
			seedExisting: true,
			valid:        true,
		},
		"nodeport_ranges_identical_are_overlapping": {
			spec:         tsapi.ProxyClassSpec{StaticEndpoints: nodePortWith([]tsapi.PortRange{{Port: 30005, EndPort: 30010}, {Port: 30005, EndPort: 30010}})},
			seedExisting: true,
			valid:        false,
		},
		"nodeport_ranges_clash_with_existing_proxyclass": {
			spec:         tsapi.ProxyClassSpec{StaticEndpoints: nodePortWith([]tsapi.PortRange{{Port: 31005, EndPort: 32070}})},
			seedExisting: true,
			valid:        false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			pc := &tsapi.ProxyClass{
				TypeMeta:   metav1.TypeMeta{Kind: "ProxyClass", APIVersion: "tailscale.com/v1alpha1"},
				ObjectMeta: metav1.ObjectMeta{Name: "pc", UID: types.UID("pc-uid")},
				Spec:       tc.spec,
			}

			objs := []client.Object{pc}
			if tc.seedExisting {
				objs = append(objs, existingPC)
			}

			fc := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme).
				WithObjects(objs...).
				WithStatusSubresource(pc, existingPC).
				Build()

			zl, err := zap.NewDevelopment()
			if err != nil {
				t.Fatal(err)
			}
			fr := record.NewFakeRecorder(10)
			pcr := proxyclass.NewReconciler(proxyclass.ReconcilerOptions{
				Client:   fc,
				Recorder: fr,
				Logger:   zl.Sugar(),
				Clock:    cl,
			})

			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: pc.Name}}
			if _, err := pcr.Reconcile(context.Background(), req); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			got := new(tsapi.ProxyClass)
			if err := fc.Get(context.Background(), types.NamespacedName{Name: pc.Name}, got); err != nil {
				t.Fatalf("Get: %v", err)
			}

			var ready *metav1.Condition
			for i := range got.Status.Conditions {
				if got.Status.Conditions[i].Type == string(tsapi.ProxyClassReady) {
					ready = &got.Status.Conditions[i]
					break
				}
			}
			if ready == nil {
				t.Fatal("Ready condition not set")
			}

			wantStatus := metav1.ConditionTrue
			if !tc.valid {
				wantStatus = metav1.ConditionFalse
			}
			if ready.Status != wantStatus {
				t.Errorf("Ready.Status = %q, want %q (reason=%q, message=%q)", ready.Status, wantStatus, ready.Reason, ready.Message)
			}
		})
	}
}
