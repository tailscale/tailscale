// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kubestore contains an ipn.StateStore implementation using Kubernetes Secrets.

package kubestore

import (
	"context"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/kube"
	"tailscale.com/types/logger"
)

// Store is an ipn.StateStore that uses a Kubernetes Secret for persistence.
type Store struct {
	client     *kube.Client
	secretName string

	memory mem.Store
}

// New returns a new Store that persists to the named secret.
func New(_ logger.Logf, secretName string) (*Store, error) {
	c, err := kube.New()
	if err != nil {
		return nil, err
	}
	s := &Store{
		client:     c,
		secretName: secretName,
	}
	// Hydrate cache with the potentially current state
	if err := s.loadState(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) loadState() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	secret, err := s.client.GetSecret(ctx, s.secretName)
	if err != nil {
		if st, ok := err.(*kube.Status); ok && st.Code == 404 {
			return nil
		}
		return err
	}
	s.memory.LoadFromMap(secret.Data)
	return nil
}

func (s *Store) String() string { return "kube.Store" }

// ReadState implements the StateStore interface.
func (s *Store) ReadState(id ipn.StateKey) ([]byte, error) {
	return s.memory.ReadState(ipn.StateKey(sanitizeKey(id)))
}

func sanitizeKey(k ipn.StateKey) string {
	// The only valid characters in a Kubernetes secret key are alphanumeric, -,
	// _, and .
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, string(k))
}

// WriteState implements the StateStore interface.
func (s *Store) WriteState(id ipn.StateKey, bs []byte) (err error) {
	defer func() {
		if err == nil {
			s.memory.WriteState(id, bs)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	secret, err := s.client.GetSecret(ctx, s.secretName)
	if err != nil {
		if st, ok := err.(*kube.Status); ok && st.Code == 404 {
			return s.client.CreateSecret(ctx, &kube.Secret{
				TypeMeta: kube.TypeMeta{
					APIVersion: "v1",
					Kind:       "Secret",
				},
				ObjectMeta: kube.ObjectMeta{
					Name: s.secretName,
				},
				Data: map[string][]byte{
					sanitizeKey(id): bs,
				},
			})
		}
		return err
	}
	secret.Data[sanitizeKey(id)] = bs
	if err := s.client.UpdateSecret(ctx, secret); err != nil {
		return err
	}
	return err
}
