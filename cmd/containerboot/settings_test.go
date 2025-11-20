// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import "testing"

func Test_parseAcceptDNS(t *testing.T) {
	tests := []struct {
		name          string
		extraArgs     string
		acceptDNS     bool
		wantExtraArgs string
		wantAcceptDNS bool
	}{
		{
			name:          "false_extra_args_unset",
			extraArgs:     "",
			wantExtraArgs: "",
			wantAcceptDNS: false,
		},
		{
			name:          "false_unrelated_args_set",
			extraArgs:     "--accept-routes=true --advertise-routes=10.0.0.1/32",
			wantExtraArgs: "--accept-routes=true --advertise-routes=10.0.0.1/32",
			wantAcceptDNS: false,
		},
		{
			name:          "true_extra_args_unset",
			extraArgs:     "",
			acceptDNS:     true,
			wantExtraArgs: "",
			wantAcceptDNS: true,
		},
		{
			name:          "true_unrelated_args_set",
			acceptDNS:     true,
			extraArgs:     "--accept-routes=true --advertise-routes=10.0.0.1/32",
			wantExtraArgs: "--accept-routes=true --advertise-routes=10.0.0.1/32",
			wantAcceptDNS: true,
		},
		{
			name:          "false_extra_args_set_to_false",
			extraArgs:     "--accept-dns=false",
			wantExtraArgs: "",
			wantAcceptDNS: false,
		},
		{
			name:          "false_extra_args_set_to_true",
			extraArgs:     "--accept-dns=true",
			wantExtraArgs: "",
			wantAcceptDNS: true,
		},
		{
			name:          "true_extra_args_set_to_false",
			extraArgs:     "--accept-dns=false",
			acceptDNS:     true,
			wantExtraArgs: "",
			wantAcceptDNS: false,
		},
		{
			name:          "true_extra_args_set_to_true",
			extraArgs:     "--accept-dns=true",
			acceptDNS:     true,
			wantExtraArgs: "",
			wantAcceptDNS: true,
		},
		{
			name:          "false_extra_args_set_to_true_implicitly",
			extraArgs:     "--accept-dns",
			wantExtraArgs: "",
			wantAcceptDNS: true,
		},
		{
			name:          "false_extra_args_set_to_true_implicitly_with_unrelated_args",
			extraArgs:     "--accept-dns --accept-routes --advertise-routes=10.0.0.1/32",
			wantExtraArgs: "--accept-routes --advertise-routes=10.0.0.1/32",
			wantAcceptDNS: true,
		},
		{
			name:          "false_extra_args_set_to_true_implicitly_surrounded_with_unrelated_args",
			extraArgs:     "--accept-routes --accept-dns --advertise-routes=10.0.0.1/32",
			wantExtraArgs: "--accept-routes --advertise-routes=10.0.0.1/32",
			wantAcceptDNS: true,
		},
		{
			name:          "true_extra_args_set_to_false_with_unrelated_args",
			extraArgs:     "--accept-routes --accept-dns=false",
			acceptDNS:     true,
			wantExtraArgs: "--accept-routes",
			wantAcceptDNS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotExtraArgs, gotAcceptDNS := parseAcceptDNS(tt.extraArgs, tt.acceptDNS)
			if gotExtraArgs != tt.wantExtraArgs {
				t.Errorf("parseAcceptDNS() gotExtraArgs = %v, want %v", gotExtraArgs, tt.wantExtraArgs)
			}
			if gotAcceptDNS != tt.wantAcceptDNS {
				t.Errorf("parseAcceptDNS() gotAcceptDNS = %v, want %v", gotAcceptDNS, tt.wantAcceptDNS)
			}
		})
	}
}
