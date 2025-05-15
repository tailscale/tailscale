// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

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

	// as part of this test, we want to create an adjacent ProxyClass in order to ensure that if it clashes with the one created in this test
	// that we get an error
	cl := tstest.NewClock(tstest.ClockOpts{})
	opc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "other-pc",
		},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Annotations: defaultProxyClassAnnotations,
			},
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
				Reason:             reasonProxyClassValid,
				Message:            reasonProxyClassValid,
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
					StatefulSet: &tsapi.StatefulSet{
						Annotations: defaultProxyClassAnnotations,
					},
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
						Reason:             reasonProxyClassValid,
						Message:            reasonProxyClassValid,
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

func TestGetRandomPort(t *testing.T) {
	for range 100 {
		port := getRandomPort()
		if port < tailscaledPortMin || port > tailscaledPortMax {
			t.Errorf("generated port %d which is out of range [%d, %d]", port, tailscaledPortMin, tailscaledPortMax)
		}
	}
}
