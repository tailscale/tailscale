// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsclient

import (
	"errors"
	"fmt"
	"sync"
)

type (
	// The Provider type is used to manage multiple Client implementations for different tailnets.
	Provider struct {
		defaultClient Client
		mu            sync.RWMutex
		clients       map[string]Client
	}
)

var (
	// ErrClientNotFound is the error given when calling Provider.For with a tailnet that has not yet been registered
	// with the provider.
	ErrClientNotFound = errors.New("client not found")
)

// NewProvider returns a new instance of the Provider type that uses the given Client implementation as the default
// client. This client will be given when calling Provider.For with a blank tailnet name.
func NewProvider(defaultClient Client) *Provider {
	return &Provider{
		defaultClient: defaultClient,
		clients:       make(map[string]Client),
	}
}

// Add a Client implementation for a given tailnet.
func (p *Provider) Add(tailnet string, client Client) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.clients[tailnet] = client
}

// Remove the Client implementation associated with the given tailnet.
func (p *Provider) Remove(tailnet string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.clients, tailnet)
}

// For returns a Client implementation associated with the given tailnet. Returns ErrClientNotFound if the given
// tailnet does not exist. Use a blank tailnet name to obtain the default Client.
func (p *Provider) For(tailnet string) (Client, error) {
	if tailnet == "" {
		return p.defaultClient, nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if client, ok := p.clients[tailnet]; ok {
		return client, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrClientNotFound, tailnet)
}
