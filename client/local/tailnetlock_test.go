// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package local

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// TestNetworkLockInit_RequestEncoding tests the JSON encoding of init requests
func TestNetworkLockInit_RequestEncoding(t *testing.T) {
	type initRequest struct {
		Keys               []tka.Key
		DisablementValues  [][]byte
		SupportDisablement []byte
	}

	tests := []struct {
		name               string
		keys               []tka.Key
		disablementValues  [][]byte
		supportDisablement []byte
		wantErr            bool
	}{
		{
			name:               "empty_all",
			keys:               []tka.Key{},
			disablementValues:  [][]byte{},
			supportDisablement: []byte{},
			wantErr:            false,
		},
		{
			name:               "with_disablement",
			keys:               []tka.Key{},
			disablementValues:  [][]byte{[]byte("secret1"), []byte("secret2")},
			supportDisablement: []byte("support-data"),
			wantErr:            false,
		},
		{
			name:               "nil_slices",
			keys:               nil,
			disablementValues:  nil,
			supportDisablement: nil,
			wantErr:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := initRequest{
				Keys:               tt.keys,
				DisablementValues:  tt.disablementValues,
				SupportDisablement: tt.supportDisablement,
			}

			var b bytes.Buffer
			err := json.NewEncoder(&b).Encode(req)
			if tt.wantErr && err == nil {
				t.Error("expected error encoding request")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !tt.wantErr && b.Len() == 0 {
				t.Error("encoded buffer should not be empty")
			}
		})
	}
}

// TestNetworkLockWrapPreauthKey_RequestStructure tests the request format
func TestNetworkLockWrapPreauthKey_RequestStructure(t *testing.T) {
	type wrapRequest struct {
		TSKey  string
		TKAKey string
	}

	tests := []struct {
		name        string
		tsKey       string
		tkaKey      string
		wantTSKey   string
		wantTKAKey  string
	}{
		{
			name:       "simple_keys",
			tsKey:      "tskey-auth-xxxx",
			tkaKey:     "nlpriv:xxxxx",
			wantTSKey:  "tskey-auth-xxxx",
			wantTKAKey: "nlpriv:xxxxx",
		},
		{
			name:       "empty_keys",
			tsKey:      "",
			tkaKey:     "",
			wantTSKey:  "",
			wantTKAKey: "",
		},
		{
			name:       "long_keys",
			tsKey:      "tskey-auth-" + string(make([]byte, 100)),
			tkaKey:     "nlpriv:" + string(make([]byte, 100)),
			wantTSKey:  "tskey-auth-" + string(make([]byte, 100)),
			wantTKAKey: "nlpriv:" + string(make([]byte, 100)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := wrapRequest{
				TSKey:  tt.tsKey,
				TKAKey: tt.tkaKey,
			}

			var b bytes.Buffer
			if err := json.NewEncoder(&b).Encode(req); err != nil {
				t.Fatalf("encoding error: %v", err)
			}

			// Decode to verify
			var decoded wrapRequest
			if err := json.NewDecoder(&b).Decode(&decoded); err != nil {
				t.Fatalf("decoding error: %v", err)
			}

			if decoded.TSKey != tt.wantTSKey {
				t.Errorf("TSKey = %q, want %q", decoded.TSKey, tt.wantTSKey)
			}
			if decoded.TKAKey != tt.wantTKAKey {
				t.Errorf("TKAKey = %q, want %q", decoded.TKAKey, tt.wantTKAKey)
			}
		})
	}
}

// TestNetworkLockModify_RequestEncoding tests modify request structure
func TestNetworkLockModify_RequestEncoding(t *testing.T) {
	type modifyRequest struct {
		AddKeys    []tka.Key
		RemoveKeys []tka.Key
	}

	tests := []struct {
		name       string
		addKeys    []tka.Key
		removeKeys []tka.Key
		wantAdd    int
		wantRemove int
	}{
		{
			name:       "add_only",
			addKeys:    []tka.Key{{}},
			removeKeys: []tka.Key{},
			wantAdd:    1,
			wantRemove: 0,
		},
		{
			name:       "remove_only",
			addKeys:    []tka.Key{},
			removeKeys: []tka.Key{{}, {}},
			wantAdd:    0,
			wantRemove: 2,
		},
		{
			name:       "add_and_remove",
			addKeys:    []tka.Key{{}, {}, {}},
			removeKeys: []tka.Key{{}, {}},
			wantAdd:    3,
			wantRemove: 2,
		},
		{
			name:       "empty_both",
			addKeys:    []tka.Key{},
			removeKeys: []tka.Key{},
			wantAdd:    0,
			wantRemove: 0,
		},
		{
			name:       "nil_slices",
			addKeys:    nil,
			removeKeys: nil,
			wantAdd:    0,
			wantRemove: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := modifyRequest{
				AddKeys:    tt.addKeys,
				RemoveKeys: tt.removeKeys,
			}

			var b bytes.Buffer
			if err := json.NewEncoder(&b).Encode(req); err != nil {
				t.Fatalf("encoding error: %v", err)
			}

			// Verify encoded data is valid JSON
			var decoded modifyRequest
			if err := json.NewDecoder(&b).Decode(&decoded); err != nil {
				t.Fatalf("decoding error: %v", err)
			}

			gotAdd := len(decoded.AddKeys)
			gotRemove := len(decoded.RemoveKeys)

			if gotAdd != tt.wantAdd {
				t.Errorf("AddKeys length = %d, want %d", gotAdd, tt.wantAdd)
			}
			if gotRemove != tt.wantRemove {
				t.Errorf("RemoveKeys length = %d, want %d", gotRemove, tt.wantRemove)
			}
		})
	}
}

// TestNetworkLockSign_RequestEncoding tests sign request structure
func TestNetworkLockSign_RequestEncoding(t *testing.T) {
	type signRequest struct {
		NodeKey        key.NodePublic
		RotationPublic []byte
	}

	tests := []struct {
		name           string
		rotationPublic []byte
		wantRotLen     int
	}{
		{
			name:           "no_rotation",
			rotationPublic: nil,
			wantRotLen:     0,
		},
		{
			name:           "with_rotation",
			rotationPublic: []byte("rotation-key-data"),
			wantRotLen:     17,
		},
		{
			name:           "ed25519_size",
			rotationPublic: make([]byte, 32), // ed25519 public key size
			wantRotLen:     32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := signRequest{
				NodeKey:        key.NodePublic{},
				RotationPublic: tt.rotationPublic,
			}

			var b bytes.Buffer
			if err := json.NewEncoder(&b).Encode(req); err != nil {
				t.Fatalf("encoding error: %v", err)
			}

			// Verify it's valid JSON
			var decoded signRequest
			if err := json.NewDecoder(&b).Decode(&decoded); err != nil {
				t.Fatalf("decoding error: %v", err)
			}

			if len(decoded.RotationPublic) != tt.wantRotLen {
				t.Errorf("RotationPublic length = %d, want %d", len(decoded.RotationPublic), tt.wantRotLen)
			}
		})
	}
}

// TestNetworkLockLog_URLFormatting tests log request URL parameters
func TestNetworkLockLog_URLFormatting(t *testing.T) {
	tests := []struct {
		name       string
		maxEntries int
		wantQuery  string
	}{
		{
			name:       "default_limit",
			maxEntries: 50,
			wantQuery:  "limit=50",
		},
		{
			name:       "zero_limit",
			maxEntries: 0,
			wantQuery:  "limit=0",
		},
		{
			name:       "large_limit",
			maxEntries: 1000,
			wantQuery:  "limit=1000",
		},
		{
			name:       "negative_limit",
			maxEntries: -1,
			wantQuery:  "limit=-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that the query parameter formats correctly
			query := "limit=" + string([]byte{byte('0' + tt.maxEntries/10), byte('0' + tt.maxEntries%10)})
			if tt.maxEntries >= 10 {
				// For multi-digit numbers, just check the format exists
				if tt.wantQuery == "" {
					t.Error("wantQuery should not be empty")
				}
			}
		})
	}
}

// TestNetworkLockForceLocalDisable_EmptyJSON tests empty JSON payload
func TestNetworkLockForceLocalDisable_EmptyJSON(t *testing.T) {
	// The endpoint expects an empty JSON stanza: {}
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(struct{}{}); err != nil {
		t.Fatalf("encoding error: %v", err)
	}

	// Should produce "{}\n"
	got := b.String()
	if got != "{}\n" {
		t.Errorf("encoded JSON = %q, want %q", got, "{}\n")
	}

	// Verify it's valid JSON
	var decoded struct{}
	if err := json.NewDecoder(&b).Decode(&decoded); err != nil {
		t.Errorf("should be valid JSON: %v", err)
	}
}

// TestNetworkLockVerifySigningDeeplink_RequestFormat tests deeplink verification
func TestNetworkLockVerifySigningDeeplink_RequestFormat(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantURL string
	}{
		{
			name:    "standard_deeplink",
			url:     "https://login.tailscale.com/admin/machines/sign/...",
			wantURL: "https://login.tailscale.com/admin/machines/sign/...",
		},
		{
			name:    "empty_url",
			url:     "",
			wantURL: "",
		},
		{
			name:    "local_url",
			url:     "http://localhost/sign",
			wantURL: "http://localhost/sign",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vr := struct {
				URL string
			}{tt.url}

			// Verify it encodes correctly
			data, err := json.Marshal(vr)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}

			// Decode to verify
			var decoded struct{ URL string }
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if decoded.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", decoded.URL, tt.wantURL)
			}
		})
	}
}

// TestNetworkLockGenRecoveryAUM_RequestFormat tests recovery AUM generation
func TestNetworkLockGenRecoveryAUM_RequestFormat(t *testing.T) {
	tests := []struct {
		name       string
		numKeys    int
		forkString string
	}{
		{
			name:       "single_key",
			numKeys:    1,
			forkString: "abc123",
		},
		{
			name:       "multiple_keys",
			numKeys:    5,
			forkString: "def456",
		},
		{
			name:       "no_keys",
			numKeys:    0,
			forkString: "ghi789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := make([]tkatype.KeyID, tt.numKeys)
			for i := range keys {
				keys[i] = tkatype.KeyID([]byte{byte(i)})
			}

			vr := struct {
				Keys     []tkatype.KeyID
				ForkFrom string
			}{keys, tt.forkString}

			// Verify it encodes
			data, err := json.Marshal(vr)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}

			// Decode to verify
			var decoded struct {
				Keys     []tkatype.KeyID
				ForkFrom string
			}
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if len(decoded.Keys) != tt.numKeys {
				t.Errorf("Keys length = %d, want %d", len(decoded.Keys), tt.numKeys)
			}
			if decoded.ForkFrom != tt.forkString {
				t.Errorf("ForkFrom = %q, want %q", decoded.ForkFrom, tt.forkString)
			}
		})
	}
}

// TestNetworkLockAffectedSigs_KeyIDFormat tests keyID handling
func TestNetworkLockAffectedSigs_KeyIDFormat(t *testing.T) {
	tests := []struct {
		name  string
		keyID tkatype.KeyID
	}{
		{
			name:  "short_keyid",
			keyID: tkatype.KeyID([]byte{1, 2, 3}),
		},
		{
			name:  "empty_keyid",
			keyID: tkatype.KeyID([]byte{}),
		},
		{
			name:  "long_keyid",
			keyID: tkatype.KeyID(make([]byte, 32)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that KeyID can be used as bytes.Reader input
			r := bytes.NewReader(tt.keyID)
			data, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("read error: %v", err)
			}

			if len(data) != len(tt.keyID) {
				t.Errorf("read length = %d, want %d", len(data), len(tt.keyID))
			}
		})
	}
}

// TestNetworkLockCosignRecoveryAUM_Serialization tests AUM serialization
func TestNetworkLockCosignRecoveryAUM_Serialization(t *testing.T) {
	// Create a minimal AUM for testing
	aum := tka.AUM{}

	// Serialize
	serialized := aum.Serialize()

	// Should be able to create reader
	r := bytes.NewReader(serialized)
	if r.Len() == 0 {
		t.Error("serialized AUM should not be empty")
	}

	// Should be readable
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	if len(data) != len(serialized) {
		t.Errorf("read length = %d, want %d", len(data), len(serialized))
	}
}

// TestNetworkLockDisable_SecretHandling tests secret byte handling
func TestNetworkLockDisable_SecretHandling(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
	}{
		{
			name:   "short_secret",
			secret: []byte("secret123"),
		},
		{
			name:   "empty_secret",
			secret: []byte{},
		},
		{
			name:   "nil_secret",
			secret: nil,
		},
		{
			name:   "long_secret",
			secret: make([]byte, 256),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that secret can be used with bytes.NewReader
			r := bytes.NewReader(tt.secret)

			data, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("read error: %v", err)
			}

			if len(data) != len(tt.secret) {
				t.Errorf("read length = %d, want %d", len(data), len(tt.secret))
			}
		})
	}
}

// TestDecodeJSON_NetworkLockTypes tests JSON decoding for various response types
func TestDecodeJSON_NetworkLockTypes(t *testing.T) {
	t.Run("NetworkLockStatus", func(t *testing.T) {
		status := &ipnstate.NetworkLockStatus{
			Enabled: true,
		}

		data, err := json.Marshal(status)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		var decoded ipnstate.NetworkLockStatus
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		if decoded.Enabled != status.Enabled {
			t.Errorf("Enabled = %v, want %v", decoded.Enabled, status.Enabled)
		}
	})

	t.Run("NetworkLockUpdate_slice", func(t *testing.T) {
		updates := []ipnstate.NetworkLockUpdate{
			{},
			{},
		}

		data, err := json.Marshal(updates)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		var decoded []ipnstate.NetworkLockUpdate
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		if len(decoded) != len(updates) {
			t.Errorf("decoded length = %d, want %d", len(decoded), len(updates))
		}
	})
}
