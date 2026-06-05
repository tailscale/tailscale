// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package proxyclass

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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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
	pcr := &Reconciler{
		Client:   fc,
		logger:   zl.Sugar(),
		clock:    cl,
		recorder: fr,
	}

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
	expectStatus(t, metav1.ConditionTrue, ReasonProxyClassValid, ReasonProxyClassValid)

	// 2. A ProxyClass resource with invalid labels gets its status updated to Invalid with an error message.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Labels = tsapi.Labels{"foo": "?!someVal"}
	})
	mustReconcile(t, "test")
	wantMsg := `ProxyClass is not valid: .spec.statefulSet.labels: Invalid value: "?!someVal": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')`
	expectStatus(t, metav1.ConditionFalse, reasonProxyClassInvalid, wantMsg)
	expectEvents(t, []string{"Warning ProxyClassInvalid " + wantMsg})

	// 3. A ProxyClass resource with invalid image reference gets its status updated to Invalid with an error message.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Labels = nil
		proxyClass.Spec.StatefulSet.Pod.TailscaleContainer.Image = "FOO bar"
	})
	mustReconcile(t, "test")
	wantMsg = `ProxyClass is not valid: spec.statefulSet.pod.tailscaleContainer.image: Invalid value: "FOO bar": invalid reference format: repository name (library/FOO bar) must be lowercase`
	expectStatus(t, metav1.ConditionFalse, reasonProxyClassInvalid, wantMsg)
	expectEvents(t, []string{"Warning ProxyClassInvalid " + wantMsg})

	// 4. A ProxyClass resource with invalid init container image reference gets its status updated to Invalid with an error message.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.StatefulSet.Pod.TailscaleContainer.Image = ""
		proxyClass.Spec.StatefulSet.Pod.TailscaleInitContainer = &tsapi.Container{Image: "FOO bar"}
	})
	mustReconcile(t, "test")
	wantMsg = `ProxyClass is not valid: spec.statefulSet.pod.tailscaleInitContainer.image: Invalid value: "FOO bar": invalid reference format: repository name (library/FOO bar) must be lowercase`
	expectStatus(t, metav1.ConditionFalse, reasonProxyClassInvalid, wantMsg)
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
	expectStatus(t, metav1.ConditionFalse, reasonProxyClassInvalid, wantMsg)
	expectEvents(t, []string{"Warning ProxyClassInvalid " + wantMsg})

	// 7. A ProxyClass with ServiceMonitor enabled in a cluster that has the ServiceMonitor CRD is valid.
	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: ServiceMonitorCRD}}
	mustCreate(t, crd)
	mustReconcile(t, "test")
	expectStatus(t, metav1.ConditionTrue, ReasonProxyClassValid, ReasonProxyClassValid)

	// 8. A ProxyClass with invalid ServiceMonitor labels gets its status updated to Invalid with an error message.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.Metrics.ServiceMonitor.Labels = tsapi.Labels{"foo": "bar!"}
	})
	mustReconcile(t, "test")
	wantMsg = `ProxyClass is not valid: .spec.metrics.serviceMonitor.labels: Invalid value: "bar!": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')`
	expectStatus(t, metav1.ConditionFalse, reasonProxyClassInvalid, wantMsg)

	// 9. A ProxyClass with valid ServiceMonitor labels gets its status updated to Valid.
	mustUpdate(t, "test", func(proxyClass *tsapi.ProxyClass) {
		proxyClass.Spec.Metrics.ServiceMonitor.Labels = tsapi.Labels{"foo": "bar", "xyz1234": "abc567", "empty": "", "onechar": "a"}
	})
	mustReconcile(t, "test")
	expectStatus(t, metav1.ConditionTrue, ReasonProxyClassValid, ReasonProxyClassValid)
}

func TestValidateProxyClassStaticEndpoints(t *testing.T) {
	for name, tc := range map[string]struct {
		staticEndpointConfig *tsapi.StaticEndpointsConfig
		valid                bool
	}{
		"no_static_endpoints": {
			staticEndpointConfig: nil,
			valid:                true,
		},
		"valid_specific_ports": {
			staticEndpointConfig: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{
					Ports: []tsapi.PortRange{
						{Port: 3001},
						{Port: 3005},
					},
					Selector: map[string]string{"kubernetes.io/hostname": "foobar"},
				},
			},
			valid: true,
		},
		"valid_port_ranges": {
			staticEndpointConfig: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{
					Ports: []tsapi.PortRange{
						{Port: 3000, EndPort: 3002},
						{Port: 3005, EndPort: 3007},
					},
					Selector: map[string]string{"kubernetes.io/hostname": "foobar"},
				},
			},
			valid: true,
		},
		"overlapping_port_ranges": {
			staticEndpointConfig: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{
					Ports: []tsapi.PortRange{
						{Port: 1000, EndPort: 2000},
						{Port: 1500, EndPort: 1800},
					},
					Selector: map[string]string{"kubernetes.io/hostname": "foobar"},
				},
			},
			valid: false,
		},
		"clashing_port_and_range": {
			staticEndpointConfig: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{
					Ports: []tsapi.PortRange{
						{Port: 3005},
						{Port: 3001, EndPort: 3010},
					},
					Selector: map[string]string{"kubernetes.io/hostname": "foobar"},
				},
			},
			valid: false,
		},
		"malformed_port_range": {
			staticEndpointConfig: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{
					Ports: []tsapi.PortRange{
						{Port: 3001, EndPort: 3000},
					},
					Selector: map[string]string{"kubernetes.io/hostname": "foobar"},
				},
			},
			valid: false,
		},
		"empty_selector": {
			staticEndpointConfig: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{
					Ports:    []tsapi.PortRange{{Port: 3000}},
					Selector: map[string]string{},
				},
			},
			valid: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			fc := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme).
				Build()
			zl, _ := zap.NewDevelopment()
			pcr := &Reconciler{
				logger: zl.Sugar(),
				Client: fc,
			}

			pc := &tsapi.ProxyClass{
				Spec: tsapi.ProxyClassSpec{
					StaticEndpoints: tc.staticEndpointConfig,
				},
			}

			logger := pcr.logger.With("ProxyClass", pc)
			err := pcr.validate(context.Background(), pc, logger)
			valid := err == nil
			if valid != tc.valid {
				t.Errorf("expected valid=%v, got valid=%v, err=%v", tc.valid, valid, err)
			}
		})
	}
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
			zl, _ := zap.NewDevelopment()
			pcr := &Reconciler{
				logger: zl.Sugar(),
			}
			logger := pcr.logger.With("ProxyClass", tc.pc)
			err := pcr.validate(context.Background(), tc.pc, logger)
			valid := err == nil
			if valid != tc.valid {
				t.Errorf("expected valid=%v, got valid=%v, err=%v", tc.valid, valid, err)
			}
		})
	}
}

func TestGetServicesNodePortRangeFromErr(t *testing.T) {
	tests := []struct {
		name   string
		errStr string
		want   string
	}{
		{
			name:   "valid_error_string",
			errStr: "NodePort 777777 is not in the allowed range 30000-32767",
			want:   "30000-32767",
		},
		{
			name:   "error_string_with_different_message",
			errStr: "some other error without a port range",
			want:   "",
		},
		{
			name:   "error_string_with_multiple_port_ranges",
			errStr: "range 1000-2000 and another range 3000-4000",
			want:   "",
		},
		{
			name:   "empty_error_string",
			errStr: "",
			want:   "",
		},
		{
			name:   "error_string_with_range_at_start",
			errStr: "30000-32767 is the range",
			want:   "30000-32767",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getServicesNodePortRangeFromErr(tt.errStr); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseServicesNodePortRange(t *testing.T) {
	tests := []struct {
		name    string
		p       string
		want    *tsapi.PortRange
		wantErr bool
	}{
		{
			name:    "valid_range",
			p:       "30000-32767",
			want:    &tsapi.PortRange{Port: 30000, EndPort: 32767},
			wantErr: false,
		},
		{
			name:    "single_port_range",
			p:       "30000",
			want:    &tsapi.PortRange{Port: 30000, EndPort: 30000},
			wantErr: false,
		},
		{
			name:    "invalid_format_non_numeric_end",
			p:       "30000-abc",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid_format_non_numeric_start",
			p:       "abc-32767",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty_string",
			p:       "",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "too_many_parts",
			p:       "1-2-3",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "port_too_large_start",
			p:       "65536-65537",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "port_too_large_end",
			p:       "30000-65536",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "inverted_range",
			p:       "32767-30000",
			want:    nil,
			wantErr: true, // IsValid() will fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			portRange, err := parseServicesNodePortRange(tt.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if portRange == nil {
				t.Fatalf("got nil port range, expected %v", tt.want)
			}

			if portRange.Port != tt.want.Port || portRange.EndPort != tt.want.EndPort {
				t.Errorf("got = %v, want %v", portRange, tt.want)
			}
		})
	}
}

func TestValidateNodePortRanges(t *testing.T) {
	tests := []struct {
		name       string
		portRanges []tsapi.PortRange
		wantErr    bool
	}{
		{
			name: "valid_ranges_with_unknown_kube_range",
			portRanges: []tsapi.PortRange{
				{Port: 30003, EndPort: 30005},
				{Port: 30006, EndPort: 30007},
			},
			wantErr: false,
		},
		{
			name: "overlapping_ranges",
			portRanges: []tsapi.PortRange{
				{Port: 30000, EndPort: 30010},
				{Port: 30005, EndPort: 30015},
			},
			wantErr: true,
		},
		{
			name: "adjacent_ranges_no_overlap",
			portRanges: []tsapi.PortRange{
				{Port: 30010, EndPort: 30020},
				{Port: 30021, EndPort: 30022},
			},
			wantErr: false,
		},
		{
			name: "identical_ranges_are_overlapping",
			portRanges: []tsapi.PortRange{
				{Port: 30005, EndPort: 30010},
				{Port: 30005, EndPort: 30010},
			},
			wantErr: true,
		},
		{
			name: "range_clashes_with_existing_proxyclass",
			portRanges: []tsapi.PortRange{
				{Port: 31005, EndPort: 32070},
			},
			wantErr: true,
		},
	}

	// Create an existing ready ProxyClass with known port ranges to test clash detection.
	cl := tstest.NewClock(tstest.ClockOpts{})
	opc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "other-pc",
		},
		Spec: tsapi.ProxyClassSpec{
			StaticEndpoints: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{
					Ports: []tsapi.PortRange{
						{Port: 31000}, {Port: 32000},
					},
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
		},
		Status: tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Type:               string(tsapi.ProxyClassReady),
				Status:             metav1.ConditionTrue,
				Reason:             ReasonProxyClassValid,
				Message:            ReasonProxyClassValid,
				LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
			}},
		},
	}

	fc := fake.NewClientBuilder().
		WithObjects(opc).
		WithStatusSubresource(opc).
		WithScheme(tsapi.GlobalScheme).
		Build()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &tsapi.ProxyClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pc",
				},
				Spec: tsapi.ProxyClassSpec{
					StaticEndpoints: &tsapi.StaticEndpointsConfig{
						NodePort: &tsapi.NodePortConfig{
							Ports: tt.portRanges,
							Selector: map[string]string{
								"foo/bar": "baz",
							},
						},
					},
				},
				Status: tsapi.ProxyClassStatus{
					Conditions: []metav1.Condition{{
						Type:               string(tsapi.ProxyClassReady),
						Status:             metav1.ConditionTrue,
						Reason:             ReasonProxyClassValid,
						Message:            ReasonProxyClassValid,
						LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
					}},
				},
			}
			err := validateNodePortRanges(context.Background(), fc, &tsapi.PortRange{Port: 30000, EndPort: 32767}, pc)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
