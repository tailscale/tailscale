// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"testing"
	"time"
)

// TestNew tests creation of a new IDPServer
func TestNew(t *testing.T) {
	srv := New(nil, "", true, false, true)

	if srv == nil {
		t.Fatal("New() returned nil")
	}

	if !srv.funnel {
		t.Error("Expected funnel to be true")
	}

	if srv.localTSMode {
		t.Error("Expected localTSMode to be false")
	}

	if !srv.enableSTS {
		t.Error("Expected enableSTS to be true")
	}

	if srv.code == nil {
		t.Error("code map not initialized")
	}

	if srv.accessToken == nil {
		t.Error("accessToken map not initialized")
	}

	if srv.refreshToken == nil {
		t.Error("refreshToken map not initialized")
	}

	if srv.funnelClients == nil {
		t.Error("funnelClients map not initialized")
	}
}

// TestSetServerURL tests setting and getting server URL
func TestSetServerURL(t *testing.T) {
	srv := New(nil, "", false, false, false)

	testURL := "https://test.example.com"
	srv.SetServerURL(testURL)

	if srv.ServerURL() != testURL {
		t.Errorf("ServerURL() = %s, want %s", srv.ServerURL(), testURL)
	}
}

// TestSetLoopbackURL tests setting loopback URL
func TestSetLoopbackURL(t *testing.T) {
	srv := New(nil, "", false, false, false)

	testURL := "http://localhost:8080"
	srv.SetLoopbackURL(testURL)

	if srv.loopbackURL != testURL {
		t.Errorf("loopbackURL = %s, want %s", srv.loopbackURL, testURL)
	}
}

// TestSetFunnelClients tests setting funnel clients
func TestSetFunnelClients(t *testing.T) {
	srv := New(nil, "", false, false, false)

	clients := map[string]*FunnelClient{
		"client1": {
			ID:           "client1",
			Secret:       "secret1",
			Name:         "Test Client 1",
			RedirectURIs: []string{"https://example.com/callback"},
			CreatedAt:    time.Now(),
		},
		"client2": {
			ID:           "client2",
			Secret:       "secret2",
			Name:         "Test Client 2",
			RedirectURIs: []string{"https://example.org/callback"},
			CreatedAt:    time.Now(),
		},
	}

	srv.SetFunnelClients(clients)

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.funnelClients) != len(clients) {
		t.Errorf("funnelClients count = %d, want %d", len(srv.funnelClients), len(clients))
	}

	for id, client := range clients {
		if srv.funnelClients[id] == nil {
			t.Errorf("Client %s not found in funnelClients", id)
			continue
		}
		if srv.funnelClients[id].ID != client.ID {
			t.Errorf("Client %s: ID mismatch", id)
		}
	}
}

// TestCleanupExpiredTokens tests token cleanup
// Migrated from legacy/tsidp_test.go:833-867
func TestCleanupExpiredTokens(t *testing.T) {
	srv := New(nil, "", false, false, false)

	now := time.Now()

	// Add expired authorization code
	srv.code["expired-code"] = &AuthRequest{
		ClientID:  "test-client",
		ValidTill: now.Add(-1 * time.Hour),
	}

	// Add valid authorization code
	srv.code["valid-code"] = &AuthRequest{
		ClientID:  "test-client",
		ValidTill: now.Add(1 * time.Hour),
	}

	// Add expired access token
	srv.accessToken["expired-token"] = &AuthRequest{
		ClientID:  "test-client",
		ValidTill: now.Add(-1 * time.Hour),
	}

	// Add valid access token
	srv.accessToken["valid-token"] = &AuthRequest{
		ClientID:  "test-client",
		ValidTill: now.Add(1 * time.Hour),
	}

	// Add expired refresh token
	srv.refreshToken["expired-refresh"] = &AuthRequest{
		ClientID:  "test-client",
		ValidTill: now.Add(-1 * time.Hour),
	}

	// Add valid refresh token (no expiry)
	srv.refreshToken["valid-refresh"] = &AuthRequest{
		ClientID: "test-client",
		// No ValidTill set means no expiry
	}

	// Run cleanup
	srv.CleanupExpiredTokens()

	// Check that expired tokens were removed
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if _, exists := srv.code["expired-code"]; exists {
		t.Error("Expired authorization code was not removed")
	}

	if _, exists := srv.code["valid-code"]; !exists {
		t.Error("Valid authorization code was incorrectly removed")
	}

	if _, exists := srv.accessToken["expired-token"]; exists {
		t.Error("Expired access token was not removed")
	}

	if _, exists := srv.accessToken["valid-token"]; !exists {
		t.Error("Valid access token was incorrectly removed")
	}

	if _, exists := srv.refreshToken["expired-refresh"]; exists {
		t.Error("Expired refresh token was not removed")
	}

	if _, exists := srv.refreshToken["valid-refresh"]; !exists {
		t.Error("Valid refresh token was incorrectly removed")
	}
}

// TestAuthRequestFields tests AuthRequest struct initialization
func TestAuthRequestFields(t *testing.T) {
	ar := &AuthRequest{
		LocalRP:     true,
		ClientID:    "test-client",
		Nonce:       "test-nonce",
		RedirectURI: "https://example.com/callback",
		Resources:   []string{"resource1", "resource2"},
		Scopes:      []string{"openid", "profile"},
		ValidTill:   time.Now().Add(5 * time.Minute),
		JTI:         "unique-jwt-id",
	}

	if !ar.LocalRP {
		t.Error("LocalRP should be true")
	}

	if ar.ClientID != "test-client" {
		t.Errorf("ClientID = %s, want test-client", ar.ClientID)
	}

	if ar.Nonce != "test-nonce" {
		t.Errorf("Nonce = %s, want test-nonce", ar.Nonce)
	}

	if len(ar.Resources) != 2 {
		t.Errorf("Resources count = %d, want 2", len(ar.Resources))
	}

	if len(ar.Scopes) != 2 {
		t.Errorf("Scopes count = %d, want 2", len(ar.Scopes))
	}
}
