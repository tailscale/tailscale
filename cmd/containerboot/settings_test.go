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
		clientSecret string
		idToken      string
		audience     string
		errContains  string
	}{
		{
			name: "no_auth_method",
		},
		{
			name:    "authkey_only",
			authKey: "tskey-auth-xxx",
		},
		{
			name:         "client_secret_only",
			clientSecret: "tskey-client-xxx",
		},
		{
			name:     "client_id_alone",
			clientID: "client-id",
		},
		{
			name:         "oauth_client_id_and_secret",
			clientID:     "client-id",
			clientSecret: "tskey-client-xxx",
		},
		{
			name:     "wif_client_id_and_id_token",
			clientID: "client-id",
			idToken:  "id-token",
		},
		{
			name:     "wif_client_id_and_audience",
			clientID: "client-id",
			audience: "audience",
		},
		{
			name:        "id_token_without_client_id",
			idToken:     "id-token",
			errContains: "TS_ID_TOKEN is set but TS_CLIENT_ID is not set",
		},
		{
			name:        "audience_without_client_id",
			audience:    "audience",
			errContains: "TS_AUDIENCE is set but TS_CLIENT_ID is not set",
		},
		{
			name:         "authkey_with_client_secret",
			authKey:      "tskey-auth-xxx",
			clientSecret: "tskey-client-xxx",
			errContains:  "TS_AUTHKEY cannot be used with",
		},
		{
			name:        "authkey_with_id_token",
			authKey:     "tskey-auth-xxx",
			clientID:    "client-id",
			idToken:     "id-token",
			errContains: "TS_AUTHKEY cannot be used with",
		},
		{
			name:        "authkey_with_audience",
			authKey:     "tskey-auth-xxx",
			clientID:    "client-id",
			audience:    "audience",
			errContains: "TS_AUTHKEY cannot be used with",
		},
		{
			name:         "id_token_with_client_secret",
			clientID:     "client-id",
			clientSecret: "tskey-client-xxx",
			idToken:      "id-token",
			errContains:  "TS_ID_TOKEN and TS_CLIENT_SECRET cannot both be set",
		},
		{
			name:        "id_token_with_audience",
			clientID:    "client-id",
			idToken:     "id-token",
			audience:    "audience",
			errContains: "TS_ID_TOKEN and TS_AUDIENCE cannot both be set",
		},
		{
			name:         "audience_with_client_secret",
			clientID:     "client-id",
			clientSecret: "tskey-client-xxx",
			audience:     "audience",
			errContains:  "TS_AUDIENCE and TS_CLIENT_SECRET cannot both be set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &settings{
				AuthKey:      tt.authKey,
				ClientID:     tt.clientID,
				ClientSecret: tt.clientSecret,
				IDToken:      tt.idToken,
				Audience:     tt.audience,
			}
			err := s.validate()
			if tt.errContains != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
