// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
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

func Test_parseAndRemoveSetFlag(t *testing.T) {
	tests := []struct {
		name          string
		extraArgs     string
		flagName      string
		envValue      string
		wantExtraArgs string
		wantSet       bool
		wantValue     string
	}{
		{
			name:          "unset",
			flagName:      "--relay-server-port",
			wantExtraArgs: "",
			wantSet:       false,
			wantValue:     "",
		},
		{
			name:          "env_only",
			flagName:      "--relay-server-port",
			envValue:      "44000",
			wantExtraArgs: "",
			wantSet:       true,
			wantValue:     "44000",
		},
		{
			name:          "extra_args_eq_form",
			extraArgs:     "--relay-server-port=44000",
			flagName:      "--relay-server-port",
			wantExtraArgs: "",
			wantSet:       true,
			wantValue:     "44000",
		},
		{
			name:          "extra_args_space_form",
			extraArgs:     "--relay-server-port 44000",
			flagName:      "--relay-server-port",
			wantExtraArgs: "",
			wantSet:       true,
			wantValue:     "44000",
		},
		{
			name:          "extra_args_overrides_env",
			extraArgs:     "--relay-server-port=44000",
			flagName:      "--relay-server-port",
			envValue:      "55000",
			wantExtraArgs: "",
			wantSet:       true,
			wantValue:     "44000",
		},
		{
			name:          "extra_args_with_unrelated_args",
			extraArgs:     "--accept-routes --relay-server-port=44000 --widget=rotated",
			flagName:      "--relay-server-port",
			wantExtraArgs: "--accept-routes --widget=rotated",
			wantSet:       true,
			wantValue:     "44000",
		},
		{
			name:          "bare_flag_no_value",
			extraArgs:     "--relay-server-port",
			flagName:      "--relay-server-port",
			wantExtraArgs: "",
			wantSet:       true,
			wantValue:     "",
		},
		{
			name:          "env_only_with_unrelated_args",
			extraArgs:     "--accept-routes",
			flagName:      "--relay-server-port",
			envValue:      "44000",
			wantExtraArgs: "--accept-routes",
			wantSet:       true,
			wantValue:     "44000",
		},
		{
			name:          "static_endpoints_flag",
			extraArgs:     "--relay-server-static-endpoints=[2001:db8::1]:40000",
			flagName:      "--relay-server-static-endpoints",
			wantExtraArgs: "",
			wantSet:       true,
			wantValue:     "[2001:db8::1]:40000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotExtraArgs, gotSet, gotValue := parseAndRemoveSetFlag(tt.extraArgs, tt.flagName, tt.envValue)
			if gotExtraArgs != tt.wantExtraArgs {
				t.Errorf("parseAndRemoveSetFlag() gotExtraArgs = %q, want %q", gotExtraArgs, tt.wantExtraArgs)
			}
			if gotSet != tt.wantSet {
				t.Errorf("parseAndRemoveSetFlag() gotSet = %v, want %v", gotSet, tt.wantSet)
			}
			if gotValue != tt.wantValue {
				t.Errorf("parseAndRemoveSetFlag() gotValue = %q, want %q", gotValue, tt.wantValue)
			}
		})
	}
}

func TestConfigFromEnvRelayServer(t *testing.T) {
	tests := []struct {
		name                       string
		relayServerPort            string
		relayServerStaticEndpoints string
		extraArgs                  string
		wantPort                   string
		wantPortSet                bool
		wantEndpoints              string
		wantEndpointsSet           bool
		wantExtraArgs              string
	}{
		{
			name: "unset",
		},
		{
			name:            "port_env_only",
			relayServerPort: "44000",
			wantPort:        "44000",
			wantPortSet:     true,
		},
		{
			name:        "port_via_extra_args",
			extraArgs:   "--relay-server-port=44000",
			wantPort:    "44000",
			wantPortSet: true,
		},
		{
			name:                       "endpoints_env_only",
			relayServerStaticEndpoints: "[2001:db8::1]:40000",
			wantEndpoints:              "[2001:db8::1]:40000",
			wantEndpointsSet:           true,
		},
		{
			name:          "extra_args_stripped",
			extraArgs:     "--accept-routes --relay-server-port=44000",
			wantPort:      "44000",
			wantPortSet:   true,
			wantExtraArgs: "--accept-routes",
		},
		{
			name:            "port_env_with_unrelated_args",
			relayServerPort: "44000",
			extraArgs:       "--accept-routes",
			wantPort:        "44000",
			wantPortSet:     true,
			wantExtraArgs:   "--accept-routes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR", "")
			t.Setenv("TS_RELAY_SERVER_PORT", tt.relayServerPort)
			t.Setenv("TS_RELAY_SERVER_STATIC_ENDPOINTS", tt.relayServerStaticEndpoints)
			t.Setenv("TS_EXTRA_ARGS", tt.extraArgs)
			cfg, err := configFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.RelayServerPort != tt.wantPort {
				t.Errorf("RelayServerPort = %q, want %q", cfg.RelayServerPort, tt.wantPort)
			}
			if cfg.RelayServerPortSet != tt.wantPortSet {
				t.Errorf("RelayServerPortSet = %v, want %v", cfg.RelayServerPortSet, tt.wantPortSet)
			}
			if cfg.RelayServerStaticEndpoints != tt.wantEndpoints {
				t.Errorf("RelayServerStaticEndpoints = %q, want %q", cfg.RelayServerStaticEndpoints, tt.wantEndpoints)
			}
			if cfg.RelayServerStaticEndpointsSet != tt.wantEndpointsSet {
				t.Errorf("RelayServerStaticEndpointsSet = %v, want %v", cfg.RelayServerStaticEndpointsSet, tt.wantEndpointsSet)
			}
			if cfg.ExtraArgs != tt.wantExtraArgs {
				t.Errorf("ExtraArgs = %q, want %q", cfg.ExtraArgs, tt.wantExtraArgs)
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

func TestConfigFromEnvEmptyDefaults(t *testing.T) {
	tests := []struct {
		env  string
		get  func(*settings) string
		want string
	}{
		{
			env:  "TS_SOCKET",
			get:  func(c *settings) string { return c.Socket },
			want: "/tmp/tailscaled.sock",
		},
		{
			env:  "TS_LOCAL_ADDR_PORT",
			get:  func(c *settings) string { return c.LocalAddrPort },
			want: "[::]:9002",
		},
		{
			env:  "TS_TEST_ONLY_ROOT",
			get:  func(c *settings) string { return c.Root },
			want: "/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			t.Setenv(tt.env, "")
			cfg, err := configFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if got := tt.get(cfg); got != tt.want {
				t.Errorf(`%s set to empty "": got %q, want default %q`, tt.env, got, tt.want)
			}
		})
	}
}

func TestConfigFromEnvKubeSecret(t *testing.T) {
	tests := []struct {
		name         string
		inKubernetes bool
		unset        bool
		value        string
		want         string
	}{
		{name: "in_kubernetes_unset", inKubernetes: true, unset: true, want: "tailscale"},
		{name: "in_kubernetes_empty", inKubernetes: true, value: "", want: ""},
		{name: "in_kubernetes_set", inKubernetes: true, value: "custom", want: "custom"},
		{name: "not_in_kubernetes_unset", inKubernetes: false, unset: true, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Setenv registers a t.Cleanup to restore the original value, so
			// route the unset cases through it rather than a bare os.Unsetenv.
			t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
			if !tt.inKubernetes {
				os.Unsetenv("KUBERNETES_SERVICE_HOST")
			}
			t.Setenv("TS_KUBE_SECRET", tt.value)
			if tt.unset {
				os.Unsetenv("TS_KUBE_SECRET")
			}
			cfg, err := configFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.KubeSecret != tt.want {
				t.Errorf("KubeSecret = %q, want %q", cfg.KubeSecret, tt.want)
			}
		})
	}
}

func TestHandlesKubeIPV6(t *testing.T) {
	t.Setenv("TS_LOCAL_ADDR_PORT", "fd7a:115c:a1e0::6c34:352:9002")
	t.Setenv("POD_IPS", "fd7a:115c:a1e0::6c34:352")

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.LocalAddrPort != "[fd7a:115c:a1e0::6c34:352]:9002" {
		t.Errorf("LocalAddrPort is not set correctly")
	}

	parsed, err := netip.ParseAddrPort(cfg.LocalAddrPort)
	if err != nil {
		t.Fatal(err)
	}

	if !parsed.Addr().Is6() {
		t.Errorf("expected v6 address but got %s", parsed)
	}

	if parsed.Port() != 9002 {
		t.Errorf("expected port 9002 but got %d", parsed.Port())
	}
}

func TestBootCtxTimeout(t *testing.T) {
	tests := []struct {
		name string
		// value is the TS_BOOT_TIMEOUT value to set; unset is true to leave
		// the env var absent entirely.
		value string
		unset bool
		// want is the expected BootCtxTimeout when wantErr is false.
		want    time.Duration
		wantErr bool
	}{
		{name: "unset_defaults_to_60s", unset: true, want: 60 * time.Second},
		{name: "empty_defaults_to_60s", value: "", want: 60 * time.Second},
		{name: "valid_override", value: "3m", want: 3 * time.Minute},
		{name: "invalid_value_is_rejected", value: "90", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TS_BOOT_TIMEOUT", tt.value)
			if tt.unset {
				os.Unsetenv("TS_BOOT_TIMEOUT")
			}
			cfg, err := configFromEnv()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("configFromEnv() succeeded, want error for TS_BOOT_TIMEOUT=%q", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.BootCtxTimeout != tt.want {
				t.Errorf("BootCtxTimeout = %v, want %v", cfg.BootCtxTimeout, tt.want)
			}
		})
	}
}
