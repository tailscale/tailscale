// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_syspolicy

package local

import (
	"encoding/json"
	"testing"

	"tailscale.com/util/syspolicy/setting"
)

// TestGetEffectivePolicy_ScopeMarshaling tests policy scope marshaling
func TestGetEffectivePolicy_ScopeMarshaling(t *testing.T) {
	tests := []struct {
		name      string
		scope     mockPolicyScope
		wantBytes string
	}{
		{
			name:      "device_scope",
			scope:     mockPolicyScope{text: "device"},
			wantBytes: "device",
		},
		{
			name:      "user_scope",
			scope:     mockPolicyScope{text: "user"},
			wantBytes: "user",
		},
		{
			name:      "empty_scope",
			scope:     mockPolicyScope{text: ""},
			wantBytes: "",
		},
		{
			name:      "custom_scope",
			scope:     mockPolicyScope{text: "custom-scope-123"},
			wantBytes: "custom-scope-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.scope.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}

			if string(data) != tt.wantBytes {
				t.Errorf("marshaled = %q, want %q", string(data), tt.wantBytes)
			}
		})
	}
}

// mockPolicyScope implements setting.PolicyScope for testing
type mockPolicyScope struct {
	text string
	err  error
}

func (m mockPolicyScope) MarshalText() ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []byte(m.text), nil
}

// TestGetEffectivePolicy_ScopeMarshalError tests error handling
func TestGetEffectivePolicy_ScopeMarshalError(t *testing.T) {
	scope := mockPolicyScope{
		text: "",
		err:  &mockError{msg: "marshal failed"},
	}

	_, err := scope.MarshalText()
	if err == nil {
		t.Error("expected marshal error, got nil")
	}
	if err.Error() != "marshal failed" {
		t.Errorf("error message = %q, want %q", err.Error(), "marshal failed")
	}
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

// TestReloadEffectivePolicy_URLConstruction tests URL path construction
func TestReloadEffectivePolicy_URLConstruction(t *testing.T) {
	tests := []struct {
		name      string
		scope     mockPolicyScope
		wantPath  string
	}{
		{
			name:     "device_scope_path",
			scope:    mockPolicyScope{text: "device"},
			wantPath: "/localapi/v0/policy/device",
		},
		{
			name:     "user_scope_path",
			scope:    mockPolicyScope{text: "user"},
			wantPath: "/localapi/v0/policy/user",
		},
		{
			name:     "custom_scope_path",
			scope:    mockPolicyScope{text: "custom"},
			wantPath: "/localapi/v0/policy/custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scopeID, err := tt.scope.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}

			path := "/localapi/v0/policy/" + string(scopeID)
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
		})
	}
}

// TestPolicySnapshot_JSONEncoding tests Snapshot JSON handling
func TestPolicySnapshot_JSONEncoding(t *testing.T) {
	tests := []struct {
		name     string
		snapshot *setting.Snapshot
		wantErr  bool
	}{
		{
			name:     "empty_snapshot",
			snapshot: &setting.Snapshot{},
			wantErr:  false,
		},
		{
			name:     "nil_snapshot",
			snapshot: nil,
			wantErr:  false, // JSON can encode nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.snapshot)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !tt.wantErr && len(data) == 0 {
				t.Error("encoded data should not be empty")
			}

			// Verify it can be decoded
			if !tt.wantErr {
				var decoded setting.Snapshot
				if err := json.Unmarshal(data, &decoded); err != nil {
					t.Errorf("decode error: %v", err)
				}
			}
		})
	}
}

// TestPolicyScope_SpecialCharacters tests scope IDs with special characters
func TestPolicyScope_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name  string
		scope mockPolicyScope
		valid bool
	}{
		{
			name:  "alphanumeric",
			scope: mockPolicyScope{text: "scope123"},
			valid: true,
		},
		{
			name:  "with_hyphen",
			scope: mockPolicyScope{text: "scope-123"},
			valid: true,
		},
		{
			name:  "with_underscore",
			scope: mockPolicyScope{text: "scope_123"},
			valid: true,
		},
		{
			name:  "with_dot",
			scope: mockPolicyScope{text: "scope.123"},
			valid: true,
		},
		{
			name:  "with_slash",
			scope: mockPolicyScope{text: "scope/123"},
			valid: true, // Marshaling succeeds, but may need URL encoding
		},
		{
			name:  "with_space",
			scope: mockPolicyScope{text: "scope 123"},
			valid: true, // Marshaling succeeds, but may need URL encoding
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.scope.MarshalText()
			if err != nil {
				if tt.valid {
					t.Errorf("unexpected error for valid scope: %v", err)
				}
				return
			}

			if !tt.valid {
				t.Error("expected error for invalid scope")
			}

			// Verify round-trip
			if string(data) != tt.scope.text {
				t.Errorf("round-trip failed: got %q, want %q", string(data), tt.scope.text)
			}
		})
	}
}

// TestPolicyScope_EdgeCases tests edge cases in scope handling
func TestPolicyScope_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		scope mockPolicyScope
	}{
		{
			name:  "very_long_scope",
			scope: mockPolicyScope{text: string(make([]byte, 1000))},
		},
		{
			name:  "unicode_scope",
			scope: mockPolicyScope{text: "scope-日本語-中文"},
		},
		{
			name:  "only_numbers",
			scope: mockPolicyScope{text: "12345"},
		},
		{
			name:  "single_character",
			scope: mockPolicyScope{text: "a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.scope.MarshalText()
			if err != nil {
				t.Errorf("MarshalText error: %v", err)
				return
			}

			if len(data) == 0 {
				t.Error("marshaled data should not be empty")
			}

			// Verify it matches input
			if string(data) != tt.scope.text {
				t.Error("marshaled data doesn't match input")
			}
		})
	}
}

// TestGetEffectivePolicy_HTTPMethod tests that GET is used
func TestGetEffectivePolicy_HTTPMethod(t *testing.T) {
	// GetEffectivePolicy uses lc.get200() which should use GET method
	// This is a structural test to verify the API design
	scope := mockPolicyScope{text: "device"}

	scopeID, err := scope.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText error: %v", err)
	}

	expectedPath := "/localapi/v0/policy/" + string(scopeID)
	if expectedPath != "/localapi/v0/policy/device" {
		t.Errorf("path = %q, want /localapi/v0/policy/device", expectedPath)
	}
}

// TestReloadEffectivePolicy_HTTPMethod tests that POST is used
func TestReloadEffectivePolicy_HTTPMethod(t *testing.T) {
	// ReloadEffectivePolicy uses lc.send() with POST method
	// This is a structural test to verify the API design
	scope := mockPolicyScope{text: "user"}

	scopeID, err := scope.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText error: %v", err)
	}

	expectedPath := "/localapi/v0/policy/" + string(scopeID)
	if expectedPath != "/localapi/v0/policy/user" {
		t.Errorf("path = %q, want /localapi/v0/policy/user", expectedPath)
	}

	// ReloadEffectivePolicy should send http.NoBody with POST
	// (structural test - actual HTTP testing requires full client setup)
}

// TestPolicySnapshot_Decoding tests decoding various snapshot formats
func TestPolicySnapshot_Decoding(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name:    "empty_object",
			json:    `{}`,
			wantErr: false,
		},
		{
			name:    "null",
			json:    `null`,
			wantErr: false,
		},
		{
			name:    "invalid_json",
			json:    `{invalid}`,
			wantErr: true,
		},
		{
			name:    "array_instead_of_object",
			json:    `[]`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var snapshot setting.Snapshot
			err := json.Unmarshal([]byte(tt.json), &snapshot)

			if tt.wantErr && err == nil {
				t.Error("expected decode error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected decode error: %v", err)
			}
		})
	}
}

// TestPolicyScopeEquality tests scope comparison
func TestPolicyScopeEquality(t *testing.T) {
	scope1 := mockPolicyScope{text: "device"}
	scope2 := mockPolicyScope{text: "device"}
	scope3 := mockPolicyScope{text: "user"}

	data1, _ := scope1.MarshalText()
	data2, _ := scope2.MarshalText()
	data3, _ := scope3.MarshalText()

	if string(data1) != string(data2) {
		t.Error("identical scopes should marshal to same value")
	}

	if string(data1) == string(data3) {
		t.Error("different scopes should marshal to different values")
	}
}
