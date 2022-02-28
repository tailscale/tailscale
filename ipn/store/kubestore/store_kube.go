// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package kubestore contains an ipn.StateStore implementation using Kubernetes Secrets.

package kubestore

import (
	"context"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/kube"
	"tailscale.com/types/logger"
)

// Store is an ipn.StateStore that uses a Kubernetes Secret for persistence.
type Store struct {
	client     *kube.Client
	secretName string
}

// New returns a new Store that persists to the named secret.
func New(_ logger.Logf, secretName string) (*Store, error) {
	c, err := kube.New()
	if err != nil {
		return nil, err
	}
	return &Store{
		client:     c,
		secretName: secretName,
	}, nil
}

func (s *Store) String() string { return "kube.Store" }

// ReadState implements the StateStore interface.
func (s *Store) ReadState(id ipn.StateKey) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	secret, err := s.client.GetSecret(ctx, s.secretName)
	if err != nil {
		if st, ok := err.(*kube.Status); ok && st.Code == 404 {
			return nil, ipn.ErrStateNotExist
		}
		return nil, err
	}
	b, ok := secret.Data[string(id)]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return b, nil
}

// WriteState implements the StateStore interface.
func (s *Store) WriteState(id ipn.StateKey, bs []byte) error {
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
					string(id): bs,
				},
			})
		}
		return err
	}
	secret.Data[string(id)] = bs
	if err := s.client.UpdateSecret(ctx, secret); err != nil {
		return err
	}
	return err
}
