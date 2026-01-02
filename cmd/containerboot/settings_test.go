// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"strings"
	"testing"
)

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

func TestValidateAuthMethods(t *testing.T) {
	tests := []struct {
		name         string
		authKey      string
		clientID     string
		idToken      string
		clientSecret string
		wantErr      bool
		errContains  string
	}{
		{
			name:    "no_auth_method",
			wantErr: false,
		},
		{
			name:    "authkey_only",
			authKey: "tskey-auth-xxx",
			wantErr: false,
		},
		{
			name:         "client_secret_only",
			clientSecret: "tskey-client-xxx",
			wantErr:      false,
		},
		{
			name:     "wif_complete",
			clientID: "client-id",
			idToken:  "id-token",
			wantErr:  false,
		},
		{
			name:         "oauth_with_client_id_and_secret",
			clientID:     "client-id",
			clientSecret: "tskey-client-xxx",
			wantErr:      false,
		},
		{
			name:        "client_id_alone",
			clientID:    "client-id",
			wantErr:     true,
			errContains: "TS_CLIENT_ID requires either TS_CLIENT_SECRET (OAuth) or TS_ID_TOKEN (WIF)",
		},
		{
			name:        "id_token_without_client_id",
			idToken:     "id-token",
			wantErr:     true,
			errContains: "TS_ID_TOKEN is set but TS_CLIENT_ID is not set",
		},
		{
			name:         "authkey_with_client_secret",
			authKey:      "tskey-auth-xxx",
			clientSecret: "tskey-client-xxx",
			wantErr:      true,
			errContains:  "TS_AUTHKEY cannot be used with",
		},
		{
			name:        "authkey_with_wif",
			authKey:     "tskey-auth-xxx",
			clientID:    "client-id",
			idToken:     "id-token",
			wantErr:     true,
			errContains: "TS_AUTHKEY cannot be used with",
		},
		{
			name:         "id_token_with_client_secret",
			clientSecret: "tskey-client-xxx",
			clientID:     "client-id",
			idToken:      "id-token",
			wantErr:      true,
			errContains:  "TS_ID_TOKEN and TS_CLIENT_SECRET cannot both be set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &settings{
				AuthKey:      tt.authKey,
				ClientID:     tt.clientID,
				ClientSecret: tt.clientSecret,
				IDToken:      tt.idToken,
			}
			err := s.validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
