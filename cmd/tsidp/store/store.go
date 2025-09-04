// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package store implements data persistence logic for the tsidp service.
package store

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"tailscale.com/cmd/tsidp/server"
)

// FunnelClientsFile is the file where client IDs and secrets for OIDC clients
// accessing the IDP over Funnel are persisted.
const FunnelClientsFile = "oidc-funnel-clients.json"

// Store handles persistence operations for the tsidp service
type Store struct {
	funnelClientsFile string
}

// New creates a new Store instance
func New() *Store {
	return &Store{
		funnelClientsFile: FunnelClientsFile,
	}
}

// LoadFunnelClients loads funnel clients from disk
// Migrated from logic in legacy/tsidp.go:172-180
func (s *Store) LoadFunnelClients() (map[string]*server.FunnelClient, error) {
	f, err := os.Open(s.funnelClientsFile)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, return empty map
			return make(map[string]*server.FunnelClient), nil
		}
		return nil, fmt.Errorf("could not open %s: %v", s.funnelClientsFile, err)
	}
	defer f.Close()

	var clients map[string]*server.FunnelClient
	if err := json.NewDecoder(f).Decode(&clients); err != nil {
		return nil, fmt.Errorf("could not parse %s: %v", s.funnelClientsFile, err)
	}

	return clients, nil
}

// SaveFunnelClients saves funnel clients to disk
// Migrated from legacy/tsidp.go:2270-2278
func (s *Store) SaveFunnelClients(clients map[string]*server.FunnelClient) error {
	data, err := json.MarshalIndent(clients, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling funnel clients: %w", err)
	}
	if err := os.WriteFile(s.funnelClientsFile, data, 0600); err != nil {
		return fmt.Errorf("writing funnel clients file: %w", err)
	}
	return nil
}

// RSAPrivateKeyJSONWrapper wraps an RSA private key for JSON serialization
// Migrated from legacy/tsidp.go:2331-2334
type RSAPrivateKeyJSONWrapper struct {
	Kid uint64 `json:"kid"`
	Key string `json:"key"` // PEM-encoded RSA private key
}

// SigningKey represents a JWT signing key
// Migrated from legacy/tsidp.go:2336-2339
type SigningKey struct {
	Kid uint64
	Key *rsa.PrivateKey
}

// MarshalJSON serializes a SigningKey to JSON
// Migrated from legacy/tsidp.go:2341-2351
func (sk *SigningKey) MarshalJSON() ([]byte, error) {
	if sk.Key == nil {
		return nil, fmt.Errorf("signing key is nil")
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(sk.Key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	wrapper := RSAPrivateKeyJSONWrapper{
		Kid: sk.Kid,
		Key: string(pem.EncodeToMemory(pemBlock)),
	}
	return json.Marshal(wrapper)
}

// UnmarshalJSON deserializes a SigningKey from JSON
// Migrated from legacy/tsidp.go:2353-2375
func (sk *SigningKey) UnmarshalJSON(b []byte) error {
	var wrapper RSAPrivateKeyJSONWrapper
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(wrapper.Key))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	sk.Kid = wrapper.Kid
	sk.Key = key
	return nil
}

// TokenStore manages token persistence (in-memory for now)
// This is a placeholder for future database integration
type TokenStore struct {
	// In the future, this could be backed by a database
}

// NewTokenStore creates a new TokenStore
func NewTokenStore() *TokenStore {
	return &TokenStore{}
}

// FunnelClientJSON is used for JSON marshaling/unmarshaling with custom time handling
// Migrated from logic in legacy/tsidp.go:2026-2053
type FunnelClientJSON struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	CreatedAt    string   `json:"created_at"`
	LastUsed     string   `json:"last_used,omitempty"`
}

// ToFunnelClient converts FunnelClientJSON to server.FunnelClient
func (c *FunnelClientJSON) ToFunnelClient() (*server.FunnelClient, error) {
	createdAt, err := time.Parse(time.RFC3339, c.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}

	client := &server.FunnelClient{
		ID:           c.ID,
		Secret:       c.Secret,
		Name:         c.Name,
		RedirectURIs: c.RedirectURIs,
		CreatedAt:    createdAt,
	}

	if c.LastUsed != "" {
		lastUsed, err := time.Parse(time.RFC3339, c.LastUsed)
		if err != nil {
			return nil, fmt.Errorf("parsing last_used: %w", err)
		}
		client.LastUsed = lastUsed
	}

	return client, nil
}

// FromFunnelClient converts server.FunnelClient to FunnelClientJSON
func FromFunnelClient(client *server.FunnelClient) *FunnelClientJSON {
	json := &FunnelClientJSON{
		ID:           client.ID,
		Secret:       client.Secret,
		Name:         client.Name,
		RedirectURIs: client.RedirectURIs,
		CreatedAt:    client.CreatedAt.Format(time.RFC3339),
	}

	if !client.LastUsed.IsZero() {
		json.LastUsed = client.LastUsed.Format(time.RFC3339)
	}

	return json
}