// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"strings"
	"testing"
)

func TestValidateVIPService(t *testing.T) {
	tests := []struct {
		name    string
		svc     VIPService
		wantErr string // empty string means no error
	}{
		{
			name:    "empty_name",
			svc:     VIPService{},
			wantErr: "VIPService name is required",
		},
		{
			name: "invalid_name_with_dot",
			svc: VIPService{
				Name: "invalid.name",
			},
			wantErr: "invalid VIPService name: name must be a valid DNS label",
		},
		{
			name: "invalid_tag",
			svc: VIPService{
				Name: "valid-name",
				Tags: []string{"invalid-tag"},
			},
			wantErr: "invalid tag",
		},
		{
			name: "valid_service_with_no_ips",
			svc: VIPService{
				Name: "valid-name",
				Tags: []string{"tag:value"},
			},
		},
		{
			name: "invalid_first_ip",
			svc: VIPService{
				Name:  "valid-name",
				Addrs: []string{"256.256.256.256"},
			},
			wantErr: "invalid IP address",
		},
		{
			name: "non_ipv4_as_first_address",
			svc: VIPService{
				Name:  "valid-name",
				Addrs: []string{"2001:db8::1"},
			},
			wantErr: "first IP address must be IPv4",
		},
		{
			name: "non_tailscale_ipv4",
			svc: VIPService{
				Name:  "valid-name",
				Addrs: []string{"192.168.1.1"},
			},
			wantErr: "is not a valid Tailscale IP",
		},
		{
			name: "too_many_addresses",
			svc: VIPService{
				Name:  "valid-name",
				Addrs: []string{"100.64.0.1", "2001:db8::1", "100.64.0.2"},
			},
			wantErr: "can have at most 2 IP addresses",
		},
		{
			name: "non_ipv6_as_second_address",
			svc: VIPService{
				Name:  "valid-name",
				Addrs: []string{"100.64.0.1", "192.168.1.1"},
			},
			wantErr: "second IP address must be IPv6",
		},
		{
			name: "invalid_second_ip",
			svc: VIPService{
				Name:  "valid-name",
				Addrs: []string{"100.64.0.1", "not-an-ip"},
			},
			wantErr: "invalid IP address at index 1",
		},
		{
			name: "valid_service_with_both_addresses",
			svc: VIPService{
				Name:  "valid-name",
				Tags:  []string{"tag:value"},
				Addrs: []string{"100.64.0.1", "2001:db8::1"},
			},
		},
		{
			name: "valid_service_with_only_ipv4",
			svc: VIPService{
				Name:  "valid-name",
				Tags:  []string{"tag:value"},
				Addrs: []string{"100.64.0.1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.svc.validateVIPService()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("validateVIPService() error = %v, wanted no error", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validateVIPService() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}
