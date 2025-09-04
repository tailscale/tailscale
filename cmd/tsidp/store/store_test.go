// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package store

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"testing"
	"time"

	"tailscale.com/cmd/tsidp/server"
)

// TestSigningKeyMarshalUnmarshal tests JSON marshaling/unmarshaling of signing keys
// Migrated from legacy/tsidp_test.go signing key tests
func TestSigningKeyMarshalUnmarshal(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	original := &SigningKey{
		Kid: 12345,
		Key: privateKey,
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal signing key: %v", err)
	}

	// Unmarshal from JSON
	var decoded SigningKey
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal signing key: %v", err)
	}

	// Verify Kid matches
	if decoded.Kid != original.Kid {
		t.Errorf("Kid mismatch: got %d, want %d", decoded.Kid, original.Kid)
	}

	// Verify key parameters match
	if decoded.Key.N.Cmp(original.Key.N) != 0 {
		t.Error("Key N parameter mismatch")
	}
	if decoded.Key.E != original.Key.E {
		t.Error("Key E parameter mismatch")
	}
	if decoded.Key.D.Cmp(original.Key.D) != 0 {
		t.Error("Key D parameter mismatch")
	}
}

// TestFunnelClientConversion tests conversion between FunnelClient and FunnelClientJSON
func TestFunnelClientConversion(t *testing.T) {
	createdAt := time.Now().Round(time.Second)
	lastUsed := createdAt.Add(time.Hour)

	original := &server.FunnelClient{
		ID:          "test-client",
		Secret:      "test-secret",
		Name:        "Test Client",
		RedirectURI: "https://example.com/callback",
		CreatedAt:   createdAt,
		LastUsed:    lastUsed,
	}

	// Convert to JSON format
	jsonClient := FromFunnelClient(original)

	// Convert back to FunnelClient
	converted, err := jsonClient.ToFunnelClient()
	if err != nil {
		t.Fatalf("Failed to convert from JSON: %v", err)
	}

	// Verify all fields match
	if converted.ID != original.ID {
		t.Errorf("ID mismatch: got %s, want %s", converted.ID, original.ID)
	}
	if converted.Secret != original.Secret {
		t.Errorf("Secret mismatch: got %s, want %s", converted.Secret, original.Secret)
	}
	if converted.Name != original.Name {
		t.Errorf("Name mismatch: got %s, want %s", converted.Name, original.Name)
	}
	if converted.RedirectURI != original.RedirectURI {
		t.Errorf("RedirectURI mismatch: got %s, want %s", converted.RedirectURI, original.RedirectURI)
	}
	if !converted.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt mismatch: got %v, want %v", converted.CreatedAt, original.CreatedAt)
	}
	if !converted.LastUsed.Equal(original.LastUsed) {
		t.Errorf("LastUsed mismatch: got %v, want %v", converted.LastUsed, original.LastUsed)
	}
}

// TestLoadFunnelClientsFileNotExist tests loading when file doesn't exist
func TestLoadFunnelClientsFileNotExist(t *testing.T) {
	store := &Store{
		funnelClientsFile: "non-existent-file.json",
	}

	clients, err := store.LoadFunnelClients()
	if err != nil {
		t.Fatalf("Expected no error for non-existent file, got: %v", err)
	}

	if len(clients) != 0 {
		t.Errorf("Expected empty map, got %d clients", len(clients))
	}
}

// TestSaveFunnelClients tests saving funnel clients to disk
func TestSaveFunnelClients(t *testing.T) {
	// Create a temporary file
	tmpfile, err := os.CreateTemp("", "test-funnel-clients-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	store := &Store{
		funnelClientsFile: tmpfile.Name(),
	}

	// Create test clients
	clients := map[string]*server.FunnelClient{
		"client1": {
			ID:          "client1",
			Secret:      "secret1",
			Name:        "Client 1",
			RedirectURI: "https://example.com/callback1",
			CreatedAt:   time.Now(),
		},
		"client2": {
			ID:          "client2",
			Secret:      "secret2",
			Name:        "Client 2",
			RedirectURI: "https://example.com/callback2",
			CreatedAt:   time.Now(),
		},
	}

	// Save clients
	if err := store.SaveFunnelClients(clients); err != nil {
		t.Fatalf("Failed to save clients: %v", err)
	}

	// Load clients back
	loaded, err := store.LoadFunnelClients()
	if err != nil {
		t.Fatalf("Failed to load clients: %v", err)
	}

	// Verify clients match
	if len(loaded) != len(clients) {
		t.Errorf("Client count mismatch: got %d, want %d", len(loaded), len(clients))
	}

	for id, original := range clients {
		loaded, exists := loaded[id]
		if !exists {
			t.Errorf("Client %s not found in loaded clients", id)
			continue
		}
		if loaded.ID != original.ID {
			t.Errorf("Client %s: ID mismatch", id)
		}
		if loaded.Secret != original.Secret {
			t.Errorf("Client %s: Secret mismatch", id)
		}
		if loaded.Name != original.Name {
			t.Errorf("Client %s: Name mismatch", id)
		}
		if loaded.RedirectURI != original.RedirectURI {
			t.Errorf("Client %s: RedirectURI mismatch", id)
		}
	}
}