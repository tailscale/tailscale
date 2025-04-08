// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubestore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
)

func TestWriteState(t *testing.T) {
	tests := []struct {
		name       string
		initial    map[string][]byte
		key        ipn.StateKey
		value      []byte
		wantData   map[string][]byte
		allowPatch bool
	}{
		{
			name: "basic_write",
			initial: map[string][]byte{
				"existing": []byte("old"),
			},
			key:   "foo",
			value: []byte("bar"),
			wantData: map[string][]byte{
				"existing": []byte("old"),
				"foo":      []byte("bar"),
			},
			allowPatch: true,
		},
		{
			name: "update_existing",
			initial: map[string][]byte{
				"foo": []byte("old"),
			},
			key:   "foo",
			value: []byte("new"),
			wantData: map[string][]byte{
				"foo": []byte("new"),
			},
			allowPatch: true,
		},
		{
			name:  "create_new_secret",
			key:   "foo",
			value: []byte("bar"),
			wantData: map[string][]byte{
				"foo": []byte("bar"),
			},
			allowPatch: true,
		},
		{
			name: "patch_denied",
			initial: map[string][]byte{
				"foo": []byte("old"),
			},
			key:   "foo",
			value: []byte("new"),
			wantData: map[string][]byte{
				"foo": []byte("new"),
			},
			allowPatch: false,
		},
		{
			name: "sanitize_key",
			initial: map[string][]byte{
				"clean-key": []byte("old"),
			},
			key:   "dirty@key",
			value: []byte("new"),
			wantData: map[string][]byte{
				"clean-key": []byte("old"),
				"dirty_key": []byte("new"),
			},
			allowPatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := tt.initial // track current state
			client := &kubeclient.FakeClient{
				GetSecretImpl: func(ctx context.Context, name string) (*kubeapi.Secret, error) {
					if secret == nil {
						return nil, &kubeapi.Status{Code: 404}
					}
					return &kubeapi.Secret{Data: secret}, nil
				},
				CheckSecretPermissionsImpl: func(ctx context.Context, name string) (bool, bool, error) {
					return tt.allowPatch, true, nil
				},
				CreateSecretImpl: func(ctx context.Context, s *kubeapi.Secret) error {
					secret = s.Data
					return nil
				},
				UpdateSecretImpl: func(ctx context.Context, s *kubeapi.Secret) error {
					secret = s.Data
					return nil
				},
				JSONPatchResourceImpl: func(ctx context.Context, name, resourceType string, patches []kubeclient.JSONPatch) error {
					if !tt.allowPatch {
						return &kubeapi.Status{Reason: "Forbidden"}
					}
					if secret == nil {
						secret = make(map[string][]byte)
					}
					for _, p := range patches {
						if p.Op == "add" && p.Path == "/data" {
							secret = p.Value.(map[string][]byte)
						} else if p.Op == "add" && strings.HasPrefix(p.Path, "/data/") {
							key := strings.TrimPrefix(p.Path, "/data/")
							secret[key] = p.Value.([]byte)
						}
					}
					return nil
				},
			}

			s := &Store{
				client:     client,
				canPatch:   tt.allowPatch,
				secretName: "ts-state",
				memory:     mem.Store{},
			}

			err := s.WriteState(tt.key, tt.value)
			if err != nil {
				t.Errorf("WriteState() error = %v", err)
				return
			}

			// Verify secret data
			if diff := cmp.Diff(secret, tt.wantData); diff != "" {
				t.Errorf("secret data mismatch (-got +want):\n%s", diff)
			}

			// Verify memory store was updated
			got, err := s.memory.ReadState(ipn.StateKey(sanitizeKey(string(tt.key))))
			if err != nil {
				t.Errorf("reading from memory store: %v", err)
			}
			if !cmp.Equal(got, tt.value) {
				t.Errorf("memory store key %q = %v, want %v", tt.key, got, tt.value)
			}
		})
	}
}

func TestWriteTLSCertAndKey(t *testing.T) {
	const (
		testDomain = "my-app.tailnetxyz.ts.net"
		testCert   = "fake-cert"
		testKey    = "fake-key"
	)

	tests := []struct {
		name            string
		initial         map[string][]byte // pre-existing cert and key
		certShareMode   string
		allowPatch      bool   // whether client can patch the Secret
		wantSecretName  string // name of the Secret where cert and key should be written
		wantSecretData  map[string][]byte
		wantMemoryStore map[ipn.StateKey][]byte
	}{
		{
			name: "basic_write",
			initial: map[string][]byte{
				"existing": []byte("old"),
			},
			allowPatch:     true,
			wantSecretName: "ts-state",
			wantSecretData: map[string][]byte{
				"existing":                     []byte("old"),
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
			wantMemoryStore: map[ipn.StateKey][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
		},
		{
			name:           "cert_share_mode_write",
			certShareMode:  "rw",
			allowPatch:     true,
			wantSecretName: "my-app.tailnetxyz.ts.net",
			wantSecretData: map[string][]byte{
				"tls.crt": []byte(testCert),
				"tls.key": []byte(testKey),
			},
		},
		{
			name: "cert_share_mode_write_update_existing",
			initial: map[string][]byte{
				"tls.crt": []byte("old-cert"),
				"tls.key": []byte("old-key"),
			},
			certShareMode:  "rw",
			allowPatch:     true,
			wantSecretName: "my-app.tailnetxyz.ts.net",
			wantSecretData: map[string][]byte{
				"tls.crt": []byte(testCert),
				"tls.key": []byte(testKey),
			},
		},
		{
			name: "update_existing",
			initial: map[string][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte("old-cert"),
				"my-app.tailnetxyz.ts.net.key": []byte("old-key"),
			},
			certShareMode:  "",
			allowPatch:     true,
			wantSecretName: "ts-state",
			wantSecretData: map[string][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
			wantMemoryStore: map[ipn.StateKey][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
		},
		{
			name:           "patch_denied",
			certShareMode:  "",
			allowPatch:     false,
			wantSecretName: "ts-state",
			wantSecretData: map[string][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
			wantMemoryStore: map[ipn.StateKey][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Set POD_NAME for testing selectors
			envknob.Setenv("POD_NAME", "ingress-proxies-1")
			defer envknob.Setenv("POD_NAME", "")

			secret := tt.initial // track current state
			client := &kubeclient.FakeClient{
				GetSecretImpl: func(ctx context.Context, name string) (*kubeapi.Secret, error) {
					if secret == nil {
						return nil, &kubeapi.Status{Code: 404}
					}
					return &kubeapi.Secret{Data: secret}, nil
				},
				CheckSecretPermissionsImpl: func(ctx context.Context, name string) (bool, bool, error) {
					return tt.allowPatch, true, nil
				},
				CreateSecretImpl: func(ctx context.Context, s *kubeapi.Secret) error {
					if s.Name != tt.wantSecretName {
						t.Errorf("CreateSecret called with wrong name, got %q, want %q", s.Name, tt.wantSecretName)
					}
					secret = s.Data
					return nil
				},
				UpdateSecretImpl: func(ctx context.Context, s *kubeapi.Secret) error {
					if s.Name != tt.wantSecretName {
						t.Errorf("UpdateSecret called with wrong name, got %q, want %q", s.Name, tt.wantSecretName)
					}
					secret = s.Data
					return nil
				},
				JSONPatchResourceImpl: func(ctx context.Context, name, resourceType string, patches []kubeclient.JSONPatch) error {
					if !tt.allowPatch {
						return &kubeapi.Status{Reason: "Forbidden"}
					}
					if name != tt.wantSecretName {
						t.Errorf("JSONPatchResource called with wrong name, got %q, want %q", name, tt.wantSecretName)
					}
					if secret == nil {
						secret = make(map[string][]byte)
					}
					for _, p := range patches {
						if p.Op == "add" && p.Path == "/data" {
							secret = p.Value.(map[string][]byte)
						} else if p.Op == "add" && strings.HasPrefix(p.Path, "/data/") {
							key := strings.TrimPrefix(p.Path, "/data/")
							secret[key] = p.Value.([]byte)
						}
					}
					return nil
				},
			}

			s := &Store{
				client:        client,
				canPatch:      tt.allowPatch,
				secretName:    tt.wantSecretName,
				certShareMode: tt.certShareMode,
				memory:        mem.Store{},
			}

			err := s.WriteTLSCertAndKey(testDomain, []byte(testCert), []byte(testKey))
			if err != nil {
				t.Errorf("WriteTLSCertAndKey() error = '%v'", err)
				return
			}

			// Verify secret data
			if diff := cmp.Diff(secret, tt.wantSecretData); diff != "" {
				t.Errorf("secret data mismatch (-got +want):\n%s", diff)
			}

			// Verify memory store was updated
			for key, want := range tt.wantMemoryStore {
				got, err := s.memory.ReadState(key)
				if err != nil {
					t.Errorf("reading from memory store: %v", err)
					continue
				}
				if !cmp.Equal(got, want) {
					t.Errorf("memory store key %q = %v, want %v", key, got, want)
				}
			}
		})
	}
}

func TestReadTLSCertAndKey(t *testing.T) {
	const (
		testDomain = "my-app.tailnetxyz.ts.net"
		testCert   = "fake-cert"
		testKey    = "fake-key"
	)

	tests := []struct {
		name          string
		memoryStore   map[ipn.StateKey][]byte // pre-existing memory store state
		certShareMode string
		domain        string
		secretData    map[string][]byte // data to return from mock GetSecret
		secretGetErr  error             // error to return from mock GetSecret
		wantCert      []byte
		wantKey       []byte
		wantErr       error
		// what should end up in memory store after the store is created
		wantMemoryStore map[ipn.StateKey][]byte
	}{
		{
			name: "found_in_memory",
			memoryStore: map[ipn.StateKey][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
			domain:   testDomain,
			wantCert: []byte(testCert),
			wantKey:  []byte(testKey),
			wantMemoryStore: map[ipn.StateKey][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
		},
		{
			name:    "not_found_in_memory",
			domain:  testDomain,
			wantErr: ipn.ErrStateNotExist,
		},
		{
			name:          "cert_share_ro_mode_found_in_secret",
			certShareMode: "ro",
			domain:        testDomain,
			secretData: map[string][]byte{
				"tls.crt": []byte(testCert),
				"tls.key": []byte(testKey),
			},
			wantCert: []byte(testCert),
			wantKey:  []byte(testKey),
			wantMemoryStore: map[ipn.StateKey][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
		},
		{
			name:          "cert_share_rw_mode_found_in_secret",
			certShareMode: "rw",
			domain:        testDomain,
			secretData: map[string][]byte{
				"tls.crt": []byte(testCert),
				"tls.key": []byte(testKey),
			},
			wantCert: []byte(testCert),
			wantKey:  []byte(testKey),
		},
		{
			name:          "cert_share_ro_mode_found_in_memory",
			certShareMode: "ro",
			memoryStore: map[ipn.StateKey][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
			domain:   testDomain,
			wantCert: []byte(testCert),
			wantKey:  []byte(testKey),
			wantMemoryStore: map[ipn.StateKey][]byte{
				"my-app.tailnetxyz.ts.net.crt": []byte(testCert),
				"my-app.tailnetxyz.ts.net.key": []byte(testKey),
			},
		},
		{
			name:          "cert_share_ro_mode_not_found",
			certShareMode: "ro",
			domain:        testDomain,
			secretGetErr:  &kubeapi.Status{Code: 404},
			wantErr:       ipn.ErrStateNotExist,
		},
		{
			name:          "cert_share_ro_mode_empty_cert_in_secret",
			certShareMode: "ro",
			domain:        testDomain,
			secretData: map[string][]byte{
				"tls.crt": {},
				"tls.key": []byte(testKey),
			},
			wantErr: ipn.ErrStateNotExist,
		},
		{
			name:          "cert_share_ro_mode_kube_api_error",
			certShareMode: "ro",
			domain:        testDomain,
			secretGetErr:  fmt.Errorf("api error"),
			wantErr:       fmt.Errorf("getting TLS Secret %q: api error", sanitizeKey(testDomain)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			client := &kubeclient.FakeClient{
				GetSecretImpl: func(ctx context.Context, name string) (*kubeapi.Secret, error) {
					if tt.secretGetErr != nil {
						return nil, tt.secretGetErr
					}
					return &kubeapi.Secret{Data: tt.secretData}, nil
				},
			}

			s := &Store{
				client:        client,
				secretName:    "ts-state",
				certShareMode: tt.certShareMode,
				memory:        mem.Store{},
			}

			// Initialize memory store
			for k, v := range tt.memoryStore {
				s.memory.WriteState(k, v)
			}

			gotCert, gotKey, err := s.ReadTLSCertAndKey(tt.domain)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ReadTLSCertAndKey() error = nil, want error containing %v", tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("ReadTLSCertAndKey() error = %v, want error containing %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("ReadTLSCertAndKey() unexpected error: %v", err)
				return
			}

			if !bytes.Equal(gotCert, tt.wantCert) {
				t.Errorf("ReadTLSCertAndKey() gotCert = %v, want %v", gotCert, tt.wantCert)
			}
			if !bytes.Equal(gotKey, tt.wantKey) {
				t.Errorf("ReadTLSCertAndKey() gotKey = %v, want %v", gotKey, tt.wantKey)
			}

			// Verify memory store contents after operation
			if tt.wantMemoryStore != nil {
				for key, want := range tt.wantMemoryStore {
					got, err := s.memory.ReadState(key)
					if err != nil {
						t.Errorf("reading from memory store: %v", err)
						continue
					}
					if !bytes.Equal(got, want) {
						t.Errorf("memory store key %q = %v, want %v", key, got, want)
					}
				}
			}
		})
	}
}

func TestNewWithClient(t *testing.T) {
	const (
		secretName = "ts-state"
		testCert   = "fake-cert"
		testKey    = "fake-key"
	)

	certSecretsLabels := map[string]string{
		"tailscale.com/secret-type": "certs",
		"tailscale.com/managed":     "true",
		"tailscale.com/proxy-group": "ingress-proxies",
	}

	// Helper function to create Secret objects for testing
	makeSecret := func(name string, labels map[string]string, certSuffix string) kubeapi.Secret {
		return kubeapi.Secret{
			ObjectMeta: kubeapi.ObjectMeta{
				Name:   name,
				Labels: labels,
			},
			Data: map[string][]byte{
				"tls.crt": []byte(testCert + certSuffix),
				"tls.key": []byte(testKey + certSuffix),
			},
		}
	}

	tests := []struct {
		name                    string
		stateSecretContents     map[string][]byte // data in state Secret
		TLSSecrets              []kubeapi.Secret  // list of TLS cert Secrets
		certMode                string
		secretGetErr            error // error to return from GetSecret
		secretsListErr          error // error to return from ListSecrets
		wantMemoryStoreContents map[ipn.StateKey][]byte
		wantErr                 error
	}{
		{
			name:                    "empty_state_secret",
			stateSecretContents:     map[string][]byte{},
			wantMemoryStoreContents: map[ipn.StateKey][]byte{},
		},
		{
			name:                    "state_secret_not_found",
			secretGetErr:            &kubeapi.Status{Code: 404},
			wantMemoryStoreContents: map[ipn.StateKey][]byte{},
		},
		{
			name:         "state_secret_get_error",
			secretGetErr: fmt.Errorf("some error"),
			wantErr:      fmt.Errorf("error loading state from kube Secret: some error"),
		},
		{
			name: "load_existing_state",
			stateSecretContents: map[string][]byte{
				"foo": []byte("bar"),
				"baz": []byte("qux"),
			},
			wantMemoryStoreContents: map[ipn.StateKey][]byte{
				"foo": []byte("bar"),
				"baz": []byte("qux"),
			},
		},
		{
			name:     "load_select_certs_in_read_only_mode",
			certMode: "ro",
			stateSecretContents: map[string][]byte{
				"foo": []byte("bar"),
			},
			TLSSecrets: []kubeapi.Secret{
				makeSecret("app1.tailnetxyz.ts.net", certSecretsLabels, "1"),
				makeSecret("app2.tailnetxyz.ts.net", certSecretsLabels, "2"),
				makeSecret("some-other-secret", nil, "3"),
				makeSecret("app3.other-proxies.ts.net", map[string]string{
					"tailscale.com/secret-type": "certs",
					"tailscale.com/managed":     "true",
					"tailscale.com/proxy-group": "some-other-proxygroup",
				}, "4"),
			},
			wantMemoryStoreContents: map[ipn.StateKey][]byte{
				"foo":                        []byte("bar"),
				"app1.tailnetxyz.ts.net.crt": []byte(testCert + "1"),
				"app1.tailnetxyz.ts.net.key": []byte(testKey + "1"),
				"app2.tailnetxyz.ts.net.crt": []byte(testCert + "2"),
				"app2.tailnetxyz.ts.net.key": []byte(testKey + "2"),
			},
		},
		{
			name:     "load_select_certs_in_read_write_mode",
			certMode: "rw",
			stateSecretContents: map[string][]byte{
				"foo": []byte("bar"),
			},
			TLSSecrets: []kubeapi.Secret{
				makeSecret("app1.tailnetxyz.ts.net", certSecretsLabels, "1"),
				makeSecret("app2.tailnetxyz.ts.net", certSecretsLabels, "2"),
				makeSecret("some-other-secret", nil, "3"),
				makeSecret("app3.other-proxies.ts.net", map[string]string{
					"tailscale.com/secret-type": "certs",
					"tailscale.com/managed":     "true",
					"tailscale.com/proxy-group": "some-other-proxygroup",
				}, "4"),
			},
			wantMemoryStoreContents: map[ipn.StateKey][]byte{
				"foo":                        []byte("bar"),
				"app1.tailnetxyz.ts.net.crt": []byte(testCert + "1"),
				"app1.tailnetxyz.ts.net.key": []byte(testKey + "1"),
				"app2.tailnetxyz.ts.net.crt": []byte(testCert + "2"),
				"app2.tailnetxyz.ts.net.key": []byte(testKey + "2"),
			},
		},
		{
			name:     "list_cert_secrets_fails",
			certMode: "ro",
			stateSecretContents: map[string][]byte{
				"foo": []byte("bar"),
			},
			secretsListErr: fmt.Errorf("list error"),
			// The error is logged but not returned, and state is still loaded
			wantMemoryStoreContents: map[ipn.StateKey][]byte{
				"foo": []byte("bar"),
			},
		},
		{
			name:     "cert_secrets_not_loaded_when_not_in_share_mode",
			certMode: "",
			stateSecretContents: map[string][]byte{
				"foo": []byte("bar"),
			},
			TLSSecrets: []kubeapi.Secret{
				makeSecret("app1.tailnetxyz.ts.net", certSecretsLabels, "1"),
			},
			wantMemoryStoreContents: map[ipn.StateKey][]byte{
				"foo": []byte("bar"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envknob.Setenv("TS_CERT_SHARE_MODE", tt.certMode)

			t.Setenv("POD_NAME", "ingress-proxies-1")

			client := &kubeclient.FakeClient{
				GetSecretImpl: func(ctx context.Context, name string) (*kubeapi.Secret, error) {
					if tt.secretGetErr != nil {
						return nil, tt.secretGetErr
					}
					if name == secretName {
						return &kubeapi.Secret{Data: tt.stateSecretContents}, nil
					}
					return nil, &kubeapi.Status{Code: 404}
				},
				CheckSecretPermissionsImpl: func(ctx context.Context, name string) (bool, bool, error) {
					return true, true, nil
				},
				ListSecretsImpl: func(ctx context.Context, selector map[string]string) (*kubeapi.SecretList, error) {
					if tt.secretsListErr != nil {
						return nil, tt.secretsListErr
					}
					var matchingSecrets []kubeapi.Secret
					for _, secret := range tt.TLSSecrets {
						matches := true
						for k, v := range selector {
							if secret.Labels[k] != v {
								matches = false
								break
							}
						}
						if matches {
							matchingSecrets = append(matchingSecrets, secret)
						}
					}
					return &kubeapi.SecretList{Items: matchingSecrets}, nil
				},
			}

			s, err := newWithClient(t.Logf, client, secretName)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("NewWithClient() error = nil, want error containing %v", tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("NewWithClient() error = %v, want error containing %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("NewWithClient() unexpected error: %v", err)
				return
			}

			// Verify memory store contents
			gotJSON, err := s.memory.ExportToJSON()
			if err != nil {
				t.Errorf("ExportToJSON failed: %v", err)
				return
			}
			var got map[ipn.StateKey][]byte
			if err := json.Unmarshal(gotJSON, &got); err != nil {
				t.Errorf("failed to unmarshal memory store JSON: %v", err)
				return
			}
			want := tt.wantMemoryStoreContents
			if want == nil {
				want = map[ipn.StateKey][]byte{}
			}
			if diff := cmp.Diff(got, want); diff != "" {
				t.Errorf("memory store contents mismatch (-got +want):\n%s", diff)
			}
		})
	}
}
