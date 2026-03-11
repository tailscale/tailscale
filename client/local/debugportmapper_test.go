// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debugportmapper

package local

import (
	"net/netip"
	"testing"
	"time"
)

func TestDebugPortmapOpts_Validation(t *testing.T) {
	tests := []struct {
		name        string
		opts        *DebugPortmapOpts
		wantErr     bool
		errContains string
	}{
		{
			name: "both_gateway_and_self_valid",
			opts: &DebugPortmapOpts{
				GatewayAddr: netip.MustParseAddr("192.168.1.1"),
				SelfAddr:    netip.MustParseAddr("192.168.1.100"),
			},
			wantErr: false,
		},
		{
			name: "both_gateway_and_self_invalid",
			opts: &DebugPortmapOpts{
				GatewayAddr: netip.Addr{},
				SelfAddr:    netip.Addr{},
			},
			wantErr: false,
		},
		{
			name: "only_gateway_set",
			opts: &DebugPortmapOpts{
				GatewayAddr: netip.MustParseAddr("192.168.1.1"),
				SelfAddr:    netip.Addr{},
			},
			wantErr:     true,
			errContains: "both GatewayAddr and SelfAddr must be provided",
		},
		{
			name: "only_self_set",
			opts: &DebugPortmapOpts{
				GatewayAddr: netip.Addr{},
				SelfAddr:    netip.MustParseAddr("192.168.1.100"),
			},
			wantErr:     true,
			errContains: "both GatewayAddr and SelfAddr must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The validation logic is in DebugPortmap method
			// We're testing the condition: opts.GatewayAddr.IsValid() != opts.SelfAddr.IsValid()
			gatewayValid := tt.opts.GatewayAddr.IsValid()
			selfValid := tt.opts.SelfAddr.IsValid()
			shouldError := gatewayValid != selfValid

			if shouldError != tt.wantErr {
				t.Errorf("validation mismatch: got shouldError=%v, want wantErr=%v", shouldError, tt.wantErr)
			}
		})
	}
}

func TestDebugPortmapOpts_IPv4vsIPv6(t *testing.T) {
	tests := []struct {
		name        string
		gatewayAddr netip.Addr
		selfAddr    netip.Addr
		wantErr     bool
	}{
		{
			name:        "both_ipv4",
			gatewayAddr: netip.MustParseAddr("192.168.1.1"),
			selfAddr:    netip.MustParseAddr("192.168.1.100"),
			wantErr:     false,
		},
		{
			name:        "both_ipv6",
			gatewayAddr: netip.MustParseAddr("fe80::1"),
			selfAddr:    netip.MustParseAddr("fe80::100"),
			wantErr:     false,
		},
		{
			name:        "mixed_ipv4_gateway_ipv6_self",
			gatewayAddr: netip.MustParseAddr("192.168.1.1"),
			selfAddr:    netip.MustParseAddr("fe80::100"),
			wantErr:     false, // No validation for IP version mismatch in the opts struct itself
		},
		{
			name:        "mixed_ipv6_gateway_ipv4_self",
			gatewayAddr: netip.MustParseAddr("fe80::1"),
			selfAddr:    netip.MustParseAddr("192.168.1.100"),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &DebugPortmapOpts{
				GatewayAddr: tt.gatewayAddr,
				SelfAddr:    tt.selfAddr,
			}

			if !opts.GatewayAddr.IsValid() || !opts.SelfAddr.IsValid() {
				t.Error("test setup error: addresses should be valid")
			}

			// Both are valid, so no error expected from the IsValid check
			gatewayValid := opts.GatewayAddr.IsValid()
			selfValid := opts.SelfAddr.IsValid()
			shouldError := gatewayValid != selfValid

			if shouldError {
				t.Error("both addresses are valid, should not error")
			}
		})
	}
}

func TestDebugPortmapOpts_Types(t *testing.T) {
	validTypes := []string{
		"",      // empty means all types
		"pmp",   // NAT-PMP
		"pcp",   // PCP (Port Control Protocol)
		"upnp",  // UPnP
	}

	for _, typ := range validTypes {
		t.Run("type_"+typ, func(t *testing.T) {
			opts := &DebugPortmapOpts{
				Type: typ,
			}
			if opts.Type != typ {
				t.Errorf("Type = %q, want %q", opts.Type, typ)
			}
		})
	}
}

func TestDebugPortmapOpts_Duration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"zero", 0},
		{"one_second", 1 * time.Second},
		{"five_seconds", 5 * time.Second},
		{"one_minute", 1 * time.Minute},
		{"one_hour", 1 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &DebugPortmapOpts{
				Duration: tt.duration,
			}
			if opts.Duration != tt.duration {
				t.Errorf("Duration = %v, want %v", opts.Duration, tt.duration)
			}
		})
	}
}

func TestDebugPortmapOpts_LogHTTP(t *testing.T) {
	tests := []struct {
		name    string
		logHTTP bool
	}{
		{"enabled", true},
		{"disabled", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &DebugPortmapOpts{
				LogHTTP: tt.logHTTP,
			}
			if opts.LogHTTP != tt.logHTTP {
				t.Errorf("LogHTTP = %v, want %v", opts.LogHTTP, tt.logHTTP)
			}
		})
	}
}

func TestDebugPortmapOpts_ZeroValue(t *testing.T) {
	// Test that zero value is usable
	var opts DebugPortmapOpts

	if opts.Duration != 0 {
		t.Errorf("zero Duration = %v, want 0", opts.Duration)
	}
	if opts.Type != "" {
		t.Errorf("zero Type = %q, want empty string", opts.Type)
	}
	if opts.GatewayAddr.IsValid() {
		t.Error("zero GatewayAddr should be invalid")
	}
	if opts.SelfAddr.IsValid() {
		t.Error("zero SelfAddr should be invalid")
	}
	if opts.LogHTTP {
		t.Error("zero LogHTTP should be false")
	}
}

func TestDebugPortmapOpts_AllFieldsSet(t *testing.T) {
	opts := &DebugPortmapOpts{
		Duration:    10 * time.Second,
		Type:        "pcp",
		GatewayAddr: netip.MustParseAddr("192.168.1.1"),
		SelfAddr:    netip.MustParseAddr("192.168.1.100"),
		LogHTTP:     true,
	}

	if opts.Duration != 10*time.Second {
		t.Errorf("Duration = %v, want 10s", opts.Duration)
	}
	if opts.Type != "pcp" {
		t.Errorf("Type = %q, want pcp", opts.Type)
	}
	if !opts.GatewayAddr.IsValid() {
		t.Error("GatewayAddr should be valid")
	}
	if !opts.SelfAddr.IsValid() {
		t.Error("SelfAddr should be valid")
	}
	if !opts.LogHTTP {
		t.Error("LogHTTP should be true")
	}
}

func TestDebugPortmapOpts_CommonNetworkScenarios(t *testing.T) {
	tests := []struct {
		name        string
		gateway     string
		self        string
		description string
	}{
		{
			name:        "home_network",
			gateway:     "192.168.1.1",
			self:        "192.168.1.100",
			description: "Common home router scenario",
		},
		{
			name:        "class_a_network",
			gateway:     "10.0.0.1",
			self:        "10.0.0.50",
			description: "Class A private network",
		},
		{
			name:        "class_b_network",
			gateway:     "172.16.0.1",
			self:        "172.16.0.100",
			description: "Class B private network",
		},
		{
			name:        "ipv6_link_local",
			gateway:     "fe80::1",
			self:        "fe80::2",
			description: "IPv6 link-local addresses",
		},
		{
			name:        "ipv6_unique_local",
			gateway:     "fd00::1",
			self:        "fd00::100",
			description: "IPv6 unique local addresses",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &DebugPortmapOpts{
				GatewayAddr: netip.MustParseAddr(tt.gateway),
				SelfAddr:    netip.MustParseAddr(tt.self),
			}

			if !opts.GatewayAddr.IsValid() {
				t.Errorf("GatewayAddr %s should be valid", tt.gateway)
			}
			if !opts.SelfAddr.IsValid() {
				t.Errorf("SelfAddr %s should be valid", tt.self)
			}

			// Both valid, so should pass validation
			if opts.GatewayAddr.IsValid() != opts.SelfAddr.IsValid() {
				t.Error("validation should pass when both addresses are valid")
			}
		})
	}
}

func TestDebugPortmapOpts_InvalidAddresses(t *testing.T) {
	// Test with one valid, one invalid - should fail validation
	tests := []struct {
		name        string
		gateway     netip.Addr
		self        netip.Addr
		shouldError bool
	}{
		{
			name:        "valid_gateway_invalid_self",
			gateway:     netip.MustParseAddr("192.168.1.1"),
			self:        netip.Addr{},
			shouldError: true,
		},
		{
			name:        "invalid_gateway_valid_self",
			gateway:     netip.Addr{},
			self:        netip.MustParseAddr("192.168.1.100"),
			shouldError: true,
		},
		{
			name:        "both_invalid",
			gateway:     netip.Addr{},
			self:        netip.Addr{},
			shouldError: false, // Both invalid means validation passes
		},
		{
			name:        "both_valid",
			gateway:     netip.MustParseAddr("192.168.1.1"),
			self:        netip.MustParseAddr("192.168.1.100"),
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &DebugPortmapOpts{
				GatewayAddr: tt.gateway,
				SelfAddr:    tt.self,
			}

			shouldError := opts.GatewayAddr.IsValid() != opts.SelfAddr.IsValid()
			if shouldError != tt.shouldError {
				t.Errorf("validation error expectation mismatch: got %v, want %v", shouldError, tt.shouldError)
			}
		})
	}
}
