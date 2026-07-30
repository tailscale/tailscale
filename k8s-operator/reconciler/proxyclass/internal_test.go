// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package proxyclass

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
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

func TestValidateNodePortRangesKubeRange(t *testing.T) {
	kubeRange := &tsapi.PortRange{Port: 30000, EndPort: 32767}

	nodePortWith := func(ports []tsapi.PortRange) *tsapi.StaticEndpointsConfig {
		return &tsapi.StaticEndpointsConfig{
			NodePort: &tsapi.NodePortConfig{
				Ports:    ports,
				Selector: map[string]string{"kubernetes.io/hostname": "foobar"},
			},
		}
	}

	tests := map[string]struct {
		ports   []tsapi.PortRange
		wantErr string
	}{
		"port_within_range": {
			ports: []tsapi.PortRange{{Port: 30500}},
		},
		"range_within_range": {
			ports: []tsapi.PortRange{{Port: 30500, EndPort: 30600}},
		},
		"port_below_range": {
			ports:   []tsapi.PortRange{{Port: 29999}},
			wantErr: "is not within Cluster configured range",
		},
		"port_above_range": {
			ports:   []tsapi.PortRange{{Port: 32768}},
			wantErr: "is not within Cluster configured range",
		},
		"end_port_above_range": {
			ports:   []tsapi.PortRange{{Port: 32000, EndPort: 33000}},
			wantErr: "is not within Cluster configured range",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pc := &tsapi.ProxyClass{
				ObjectMeta: metav1.ObjectMeta{Name: "pc"},
				Spec:       tsapi.ProxyClassSpec{StaticEndpoints: nodePortWith(tc.ports)},
			}
			fc := fake.NewClientBuilder().WithScheme(tsapi.GlobalScheme).WithObjects(pc).Build()

			err := validateNodePortRanges(context.Background(), fc, kubeRange, pc)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
