// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wif

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testTenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testAudience = "11111111-2222-3333-4444-555555555555"
)

// clearAzureEnv unsets every env var the Azure code paths consult so a test
// starts from a clean, non-Azure environment.
func clearAzureEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_AUTHORITY_HOST", "AZURE_FEDERATED_TOKEN_FILE",
		"IDENTITY_ENDPOINT", "IDENTITY_HEADER",
		"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
		"ECS_CONTAINER_METADATA_URI_V4",
	} {
		t.Setenv(k, "")
	}
}

func setAzureIMDSBase(t *testing.T, base string) {
	t.Helper()
	old := azureIMDSBase
	azureIMDSBase = base
	t.Cleanup(func() { azureIMDSBase = old })
}

// managedIdentityServer is a fake IMDS / IDENTITY_ENDPOINT token service. It
// records the last request and replies with handler if non-nil, or a token.
func managedIdentityServer(t *testing.T, handler http.HandlerFunc) (srv *httptest.Server, last **http.Request) {
	t.Helper()
	last = new(*http.Request)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*last = r
		if r.Method != "GET" {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "eyJ.mi.token", "expires_in": "86399", "token_type": "Bearer", "resource": r.URL.Query().Get("resource"),
		})
	}))
	t.Cleanup(srv.Close)
	return srv, last
}

// entraServer is a fake Entra v2.0 token endpoint. It records the last
// request's path and form and replies with handler if non-nil, or a token.
func entraServer(t *testing.T, handler http.HandlerFunc) (srv *httptest.Server, lastPath *string, lastForm *map[string]string) {
	t.Helper()
	lastPath = new(string)
	lastForm = new(map[string]string)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*lastPath = r.URL.Path
		if r.Method != "POST" {
			t.Errorf("entra method = %q, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("entra Content-Type = %q", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		m := map[string]string{}
		for k := range r.PostForm {
			m[k] = r.PostForm.Get(k)
		}
		*lastForm = m
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token_type":"Bearer","expires_in":3599,"access_token":"eyJ.entra.token"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, lastPath, lastForm
}

func TestDetectEnvironmentAzureEnvVars(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want Environment
	}{
		{
			name: "identity-endpoint",
			env: map[string]string{
				"IDENTITY_ENDPOINT": "http://127.0.0.1:41000/msi/token",
				"IDENTITY_HEADER":   "secret",
			},
			want: EnvAzure,
		},
		{
			name: "workload-identity",
			env: map[string]string{
				"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/azure/tokens/azure-identity-token",
				"AZURE_CLIENT_ID":            "client",
				"AZURE_TENANT_ID":            testTenantID,
			},
			want: EnvAzure,
		},
		{
			name: "github-wins-over-azure",
			env: map[string]string{
				"ACTIONS_ID_TOKEN_REQUEST_URL":   "https://example.invalid/token",
				"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "gh",
				"IDENTITY_ENDPOINT":              "http://127.0.0.1:41000/msi/token",
				"IDENTITY_HEADER":                "secret",
			},
			want: EnvGitHub,
		},
		{
			name: "azure-env-wins-over-ecs",
			env: map[string]string{
				"ECS_CONTAINER_METADATA_URI_V4": "http://169.254.170.2/v4/x",
				"IDENTITY_ENDPOINT":             "http://127.0.0.1:41000/msi/token",
				"IDENTITY_HEADER":               "secret",
			},
			want: EnvAzure,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAzureEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if got := detectEnvironment(context.Background()); got != tt.want {
				t.Errorf("detectEnvironment() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("incomplete-signals", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv("IDENTITY_ENDPOINT", "http://127.0.0.1:41000/msi/token")
		if detectAzureEnv() {
			t.Error("detectAzureEnv() = true with IDENTITY_ENDPOINT but no IDENTITY_HEADER")
		}
		t.Setenv("IDENTITY_ENDPOINT", "")
		t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/token")
		if detectAzureEnv() {
			t.Error("detectAzureEnv() = true with token file but no client/tenant")
		}
	})
}

func TestDetectAzureIMDS(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    bool
	}{
		{
			name: "azure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/metadata/instance/compute" {
					t.Errorf("path = %q", r.URL.Path)
				}
				if r.URL.Query().Get("api-version") != azureIMDSInstanceAPIVersion {
					t.Errorf("api-version = %q", r.URL.Query().Get("api-version"))
				}
				if r.Header.Get("Metadata") != "true" {
					t.Errorf("Metadata header = %q, want true", r.Header.Get("Metadata"))
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"azEnvironment":"AZUREPUBLICCLOUD","name":"vm"}`))
			},
			want: true,
		},
		{
			name: "azure-mixed-case",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"azEnvironment":"AzureUSGovernmentCloud"}`))
			},
			want: true,
		},
		{
			name: "aws-imds-404",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "EC2ws")
				w.WriteHeader(http.StatusNotFound)
			},
			want: false,
		},
		{
			name: "non-azure-json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"azEnvironment":"SomethingElse"}`))
			},
			want: false,
		},
		{
			name: "malformed",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`not json`))
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			setAzureIMDSBase(t, srv.URL)
			if got := detectAzureIMDS(context.Background(), azureLocalHTTPClient()); got != tt.want {
				t.Errorf("detectAzureIMDS() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("unreachable", func(t *testing.T) {
		setAzureIMDSBase(t, "http://127.0.0.1:1")
		if detectAzureIMDS(context.Background(), azureLocalHTTPClient()) {
			t.Error("detectAzureIMDS() = true for closed port")
		}
	})
}

// TestAcquireAzureIDTokenIMDS covers the VM flow: the managed identity token
// from IMDS for the audience is itself the ID token.
func TestAcquireAzureIDTokenIMDS(t *testing.T) {
	tests := []struct {
		name         string
		audience     string
		env          map[string]string
		imds         http.HandlerFunc // nil: well-behaved IMDS
		wantResource string
		wantClientID string // expected client_id query param, "" for absent
		want         string
		wantErr      string
	}{
		{
			name:         "system-assigned",
			audience:     testAudience,
			wantResource: testAudience,
			want:         "eyJ.mi.token",
		},
		{
			name:         "app-id-uri-audience",
			audience:     " api://" + testAudience + " ",
			wantResource: "api://" + testAudience,
			want:         "eyJ.mi.token",
		},
		{
			name:         "user-assigned",
			audience:     testAudience,
			env:          map[string]string{"AZURE_CLIENT_ID": "user-assigned-mi"},
			wantResource: testAudience,
			wantClientID: "user-assigned-mi",
			want:         "eyJ.mi.token",
		},
		{
			name:     "imds-no-identity",
			audience: testAudience,
			imds: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_request","error_description":"Identity not found"}`))
			},
			wantErr: "azure managed identity endpoint returned 400 Bad Request: {\"error\":\"invalid_request\"",
		},
		{
			name:     "imds-malformed",
			audience: testAudience,
			imds: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{`))
			},
			wantErr: "decode azure managed identity response",
		},
		{
			name:     "imds-empty-token",
			audience: testAudience,
			imds: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"access_token":" "}`))
			},
			wantErr: "empty token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAzureEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			imds, last := managedIdentityServer(t, tt.imds)
			setAzureIMDSBase(t, imds.URL)

			got, err := acquireAzureIDToken(context.Background(), tt.audience)
			checkResult(t, got, err, tt.want, tt.wantErr)

			r := *last
			if r == nil {
				t.Fatal("IMDS was not called")
			}
			wantResource := tt.wantResource
			if wantResource == "" {
				wantResource = strings.TrimSpace(tt.audience)
			}
			if r.URL.Path != "/metadata/identity/oauth2/token" {
				t.Errorf("path = %q", r.URL.Path)
			}
			q := r.URL.Query()
			if q.Get("api-version") != azureIMDSTokenAPIVersion {
				t.Errorf("api-version = %q", q.Get("api-version"))
			}
			if got := q.Get("resource"); got != wantResource {
				t.Errorf("resource = %q, want %q", got, wantResource)
			}
			if got := q.Get("client_id"); got != tt.wantClientID {
				t.Errorf("client_id = %q, want %q", got, tt.wantClientID)
			}
			if r.Header.Get("Metadata") != "true" {
				t.Errorf("Metadata header = %q, want true", r.Header.Get("Metadata"))
			}
		})
	}
}

// TestAcquireAzureIDTokenIdentityEndpoint covers the App Service / Functions /
// Container Apps flow, where the token comes from IDENTITY_ENDPOINT.
func TestAcquireAzureIDTokenIdentityEndpoint(t *testing.T) {
	clearAzureEnv(t)
	msi, last := managedIdentityServer(t, nil)
	t.Setenv("IDENTITY_ENDPOINT", msi.URL+"/msi/token")
	t.Setenv("IDENTITY_HEADER", "header-secret")
	t.Setenv("AZURE_CLIENT_ID", "user-assigned-mi")
	// IMDS must not be consulted when the identity endpoint is present.
	setAzureIMDSBase(t, "http://127.0.0.1:1")

	got, err := acquireAzureIDToken(context.Background(), testAudience)
	checkResult(t, got, err, "eyJ.mi.token", "")

	r := *last
	if r == nil {
		t.Fatal("identity endpoint was not called")
	}
	if r.URL.Path != "/msi/token" {
		t.Errorf("path = %q", r.URL.Path)
	}
	q := r.URL.Query()
	if q.Get("api-version") != azureIdentityEndpointAPIVersion {
		t.Errorf("api-version = %q", q.Get("api-version"))
	}
	if q.Get("resource") != testAudience {
		t.Errorf("resource = %q", q.Get("resource"))
	}
	if q.Get("client_id") != "user-assigned-mi" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if r.Header.Get("X-IDENTITY-HEADER") != "header-secret" {
		t.Errorf("X-IDENTITY-HEADER = %q", r.Header.Get("X-IDENTITY-HEADER"))
	}
	if r.Header.Get("Metadata") != "" {
		t.Errorf("unexpected Metadata header %q", r.Header.Get("Metadata"))
	}
}

// TestAcquireAzureIDTokenWorkloadIdentity covers the AKS flow: the projected
// service account token is exchanged at Entra as a client assertion.
func TestAcquireAzureIDTokenWorkloadIdentity(t *testing.T) {
	tests := []struct {
		name      string
		assertion string // file contents; "" means no file
		entra     http.HandlerFunc
		wantScope string
		want      string
		wantErr   string
	}{
		{
			name:      "ok",
			assertion: "eyJ.k8s.token\n",
			wantScope: testAudience + "/.default",
			want:      "eyJ.entra.token",
		},
		{
			name:    "missing-token-file",
			wantErr: "read AZURE_FEDERATED_TOKEN_FILE",
		},
		{
			name:      "empty-token-file",
			assertion: " \n",
			wantErr:   "client assertion is empty",
		},
		{
			name:      "entra-no-federated-credential",
			assertion: "eyJ.k8s.token",
			entra: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS700213: No matching federated identity record found"}`))
			},
			wantErr: `azure token endpoint returned 401 Unauthorized: {"error":"invalid_client"`,
		},
		{
			name:      "entra-malformed",
			assertion: "eyJ.k8s.token",
			entra: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`<html>`))
			},
			wantErr: "decode azure token response",
		},
		{
			name:      "entra-empty-token",
			assertion: "eyJ.k8s.token",
			entra: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"access_token":" "}`))
			},
			wantErr: "azure token response contained empty token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAzureEnv(t)
			tokenFile := filepath.Join(t.TempDir(), "azure-identity-token")
			if tt.assertion != "" {
				if err := os.WriteFile(tokenFile, []byte(tt.assertion), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("AZURE_FEDERATED_TOKEN_FILE", tokenFile)
			t.Setenv("AZURE_CLIENT_ID", "federated-client")
			t.Setenv("AZURE_TENANT_ID", testTenantID)
			// Neither local endpoint may be consulted on this path.
			setAzureIMDSBase(t, "http://127.0.0.1:1")

			entra, entraPath, entraForm := entraServer(t, tt.entra)
			t.Setenv("AZURE_AUTHORITY_HOST", entra.URL+"/")

			got, err := acquireAzureIDToken(context.Background(), testAudience)
			checkResult(t, got, err, tt.want, tt.wantErr)
			if tt.wantErr != "" {
				return
			}
			if want := "/" + testTenantID + "/oauth2/v2.0/token"; *entraPath != want {
				t.Errorf("entra path = %q, want %q", *entraPath, want)
			}
			for k, want := range map[string]string{
				"grant_type":            "client_credentials",
				"client_id":             "federated-client",
				"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				"client_assertion":      strings.TrimSpace(tt.assertion),
				"scope":                 tt.wantScope,
			} {
				if got := (*entraForm)[k]; got != want {
					t.Errorf("entra form[%q] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestAzureScopeForAudience(t *testing.T) {
	tests := []struct {
		audience string
		want     string
	}{
		{testAudience, testAudience + "/.default"},
		{"api://tailscale-wif", "api://tailscale-wif/.default"},
		{"api://tailscale-wif/", "api://tailscale-wif/.default"},
		{"api://tailscale-wif/.default", "api://tailscale-wif/.default"},
		{" api://tailscale-wif ", "api://tailscale-wif/.default"},
	}
	for _, tt := range tests {
		t.Run(strings.NewReplacer("/", "_", ":", "", " ", "").Replace(tt.audience), func(t *testing.T) {
			if got := azureScopeForAudience(tt.audience); got != tt.want {
				t.Errorf("azureScopeForAudience(%q) = %q, want %q", tt.audience, got, tt.want)
			}
		})
	}
}

func TestAcquireAzureIDTokenRequiresAudience(t *testing.T) {
	clearAzureEnv(t)
	setAzureIMDSBase(t, "http://127.0.0.1:1")
	_, err := acquireAzureIDToken(context.Background(), "  ")
	if err == nil || !strings.Contains(err.Error(), "require an audience") {
		t.Errorf("err = %v, want audience error", err)
	}
}

func TestAcquireAzureIDTokenTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	clearAzureEnv(t)
	setAzureIMDSBase(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := acquireAzureIDToken(ctx, testAudience)
	if err == nil || !strings.Contains(err.Error(), "call azure managed identity endpoint") {
		t.Errorf("err = %v, want request error", err)
	}
}

func checkResult(t *testing.T, got string, err error, want, wantErr string) {
	t.Helper()
	if wantErr != "" {
		if err == nil {
			t.Fatalf("error = nil, want %q", wantErr)
		}
		if !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("error = %q, want containing %q", err.Error(), wantErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("token = %q, want %q", got, want)
	}
}
