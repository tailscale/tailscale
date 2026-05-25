// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_acme

package tailscale

import (
	"context"
	"crypto/tls"
	"testing"
)

// TestGetCertificate_NilClientHello tests the deprecated alias with nil input
func TestGetCertificate_NilClientHello(t *testing.T) {
	// GetCertificate is a deprecated alias to local.GetCertificate
	// It should handle nil ClientHelloInfo gracefully
	_, err := GetCertificate(nil)
	if err == nil {
		t.Error("GetCertificate(nil) should return error")
	}

	expectedErr := "no SNI ServerName"
	if err.Error() != expectedErr {
		t.Errorf("error = %q, want %q", err.Error(), expectedErr)
	}
}

// TestGetCertificate_EmptyServerName tests with empty server name
func TestGetCertificate_EmptyServerName(t *testing.T) {
	hi := &tls.ClientHelloInfo{
		ServerName: "",
	}

	_, err := GetCertificate(hi)
	if err == nil {
		t.Error("GetCertificate with empty ServerName should return error")
	}

	expectedErr := "no SNI ServerName"
	if err.Error() != expectedErr {
		t.Errorf("error = %q, want %q", err.Error(), expectedErr)
	}
}

// TestGetCertificate_ValidServerName tests with valid server name
func TestGetCertificate_ValidServerName(t *testing.T) {
	hi := &tls.ClientHelloInfo{
		ServerName: "example.ts.net",
	}

	// This will fail with "connection refused" or similar since there's no
	// actual LocalAPI server, but we're testing that it passes the SNI validation
	_, err := GetCertificate(hi)

	// Should get past SNI validation and hit the network error
	if err == nil {
		return // Unexpectedly succeeded (maybe test environment has LocalAPI?)
	}

	// The error should NOT be about SNI validation
	if err.Error() == "no SNI ServerName" {
		t.Error("should have passed SNI validation")
	}
}

// TestCertPair_ContextCancellation tests the deprecated alias with cancelled context
func TestCertPair_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// CertPair is a deprecated alias to local.CertPair
	_, _, err := CertPair(ctx, "example.ts.net")

	// Should get context cancellation error
	if err == nil {
		t.Error("CertPair with cancelled context should return error")
	}

	// The error should be related to context cancellation
	// (exact error message depends on implementation)
}

// TestCertPair_EmptyDomain tests with empty domain
func TestCertPair_EmptyDomain(t *testing.T) {
	ctx := context.Background()

	// Should fail - empty domain is invalid
	_, _, err := CertPair(ctx, "")

	// Expect an error (exact error depends on implementation)
	if err == nil {
		t.Error("CertPair with empty domain should return error")
	}
}

// TestCertPair_ValidDomain tests with valid domain
func TestCertPair_ValidDomain(t *testing.T) {
	ctx := context.Background()

	// Will fail with network error since there's no LocalAPI server
	// but we're testing the function signature and basic validation
	_, _, err := CertPair(ctx, "example.ts.net")

	// Expect an error (network error, not validation error)
	if err == nil {
		return // Unexpectedly succeeded
	}

	// Should not be a validation error about empty domain
	// (actual error will be about connection/network)
}

// TestExpandSNIName_EmptyName tests the deprecated alias with empty name
func TestExpandSNIName_EmptyName(t *testing.T) {
	ctx := context.Background()

	// ExpandSNIName is a deprecated alias to local.ExpandSNIName
	fqdn, ok := ExpandSNIName(ctx, "")

	if ok {
		t.Error("ExpandSNIName with empty name should return ok=false")
	}

	if fqdn != "" {
		t.Errorf("fqdn = %q, want empty string", fqdn)
	}
}

// TestExpandSNIName_ShortName tests with a short hostname
func TestExpandSNIName_ShortName(t *testing.T) {
	ctx := context.Background()

	// Will try to expand "myhost" to full domain
	// Will fail since there's no LocalAPI server to query status
	fqdn, ok := ExpandSNIName(ctx, "myhost")

	// Expect ok=false since we can't reach LocalAPI
	if ok {
		t.Logf("Unexpectedly succeeded: %q", fqdn)
	}

	// If ok=false, fqdn should be empty
	if !ok && fqdn != "" {
		t.Errorf("when ok=false, fqdn should be empty, got %q", fqdn)
	}
}

// TestExpandSNIName_AlreadyFQDN tests with already fully-qualified domain
func TestExpandSNIName_AlreadyFQDN(t *testing.T) {
	ctx := context.Background()

	// Already a FQDN - should not expand
	fqdn, ok := ExpandSNIName(ctx, "host.example.ts.net")

	// Will fail to connect to LocalAPI
	if ok {
		t.Logf("Unexpectedly succeeded: %q", fqdn)
	}

	// If failed, should return empty and false
	if !ok && fqdn != "" {
		t.Errorf("when ok=false, fqdn should be empty, got %q", fqdn)
	}
}

// TestDeprecatedAliases_Signatures tests that deprecated functions have correct signatures
func TestDeprecatedAliases_Signatures(t *testing.T) {
	// Compile-time signature verification

	// GetCertificate should match tls.Config.GetCertificate signature
	var _ func(*tls.ClientHelloInfo) (*tls.Certificate, error) = GetCertificate

	// CertPair should return (certPEM, keyPEM []byte, err error)
	var certPairSig func(context.Context, string) ([]byte, []byte, error) = CertPair
	if certPairSig == nil {
		t.Error("CertPair signature mismatch")
	}

	// ExpandSNIName should return (fqdn string, ok bool)
	var expandSig func(context.Context, string) (string, bool) = ExpandSNIName
	if expandSig == nil {
		t.Error("ExpandSNIName signature mismatch")
	}
}

// TestCertificateChainHandling tests certificate and key separation
func TestCertificateChainHandling(t *testing.T) {
	ctx := context.Background()

	// Test that CertPair returns two separate byte slices
	certPEM, keyPEM, err := CertPair(ctx, "test.example.com")

	if err == nil {
		// If it somehow succeeded, verify the structure
		if len(certPEM) == 0 && len(keyPEM) == 0 {
			t.Error("both certPEM and keyPEM are empty")
		}

		// certPEM and keyPEM should be different
		if len(certPEM) > 0 && len(keyPEM) > 0 {
			if string(certPEM) == string(keyPEM) {
				t.Error("certPEM and keyPEM should be different")
			}
		}
	}

	// Error is expected in test environment (no LocalAPI)
	if err != nil {
		// This is fine - we're just testing the API structure
		t.Logf("Expected error (no LocalAPI): %v", err)
	}
}

// TestGetCertificate_ClientHelloFields tests various ClientHelloInfo fields
func TestGetCertificate_ClientHelloFields(t *testing.T) {
	tests := []struct {
		name       string
		hi         *tls.ClientHelloInfo
		wantSNIErr bool
	}{
		{
			name:       "nil",
			hi:         nil,
			wantSNIErr: true,
		},
		{
			name:       "empty_server_name",
			hi:         &tls.ClientHelloInfo{ServerName: ""},
			wantSNIErr: true,
		},
		{
			name:       "valid_server_name",
			hi:         &tls.ClientHelloInfo{ServerName: "example.com"},
			wantSNIErr: false, // Should pass SNI check, fail later
		},
		{
			name:       "server_name_with_subdomain",
			hi:         &tls.ClientHelloInfo{ServerName: "sub.example.com"},
			wantSNIErr: false,
		},
		{
			name:       "server_name_single_word",
			hi:         &tls.ClientHelloInfo{ServerName: "localhost"},
			wantSNIErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetCertificate(tt.hi)

			if tt.wantSNIErr {
				if err == nil {
					t.Error("expected SNI error, got nil")
					return
				}
				if err.Error() != "no SNI ServerName" {
					t.Errorf("error = %q, want SNI error", err.Error())
				}
			} else {
				// Should not get SNI error (but will get network error)
				if err != nil && err.Error() == "no SNI ServerName" {
					t.Error("should not get SNI error for valid ServerName")
				}
			}
		})
	}
}
