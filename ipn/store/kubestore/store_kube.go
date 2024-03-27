// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kubestore contains an ipn.StateStore implementation using Kubernetes Secrets.

package kubestore

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/kube"
	"tailscale.com/types/logger"
)

// Store is an ipn.StateStore that uses a Kubernetes Secret for persistence.
type Store struct {
	client     kube.Client
	canPatch   bool
	secretName string
}

// New returns a new Store that persists to the named secret.
func New(_ logger.Logf, secretName string) (*Store, error) {
	c, err := kube.New()
	if err != nil {
		return nil, err
	}
	canPatch, _, err := c.CheckSecretPermissions(context.Background(), secretName)
	if err != nil {
		return nil, err
	}
	return &Store{
		client:     c,
		canPatch:   canPatch,
		secretName: secretName,
	}, nil
}

func (s *Store) SetDialer(d func(ctx context.Context, network, address string) (net.Conn, error)) {
	s.client.SetDialer(d)
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
	b, ok := secret.Data[sanitizeKey(id)]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return b, nil
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
func (s *Store) WriteState(id ipn.StateKey, bs []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	secret, err := s.client.GetSecret(ctx, s.secretName)
	if err != nil {
		if kube.IsNotFoundErr(err) {
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
	if s.canPatch {
		if len(secret.Data) == 0 { // if user has pre-created a blank Secret
			m := []kube.JSONPatch{
				{
					Op:    "add",
					Path:  "/data",
					Value: map[string][]byte{sanitizeKey(id): bs},
				},
			}
			if err := s.client.JSONPatchSecret(ctx, s.secretName, m); err != nil {
				return fmt.Errorf("error patching Secret %s with a /data field: %v", s.secretName, err)
			}
			return nil
		}
		m := []kube.JSONPatch{
			{
				Op:    "add",
				Path:  "/data/" + sanitizeKey(id),
				Value: bs,
			},
		}
		if err := s.client.JSONPatchSecret(ctx, s.secretName, m); err != nil {
			return fmt.Errorf("error patching Secret %s with /data/%s field", s.secretName, sanitizeKey(id))
		}
		return nil
	}
	secret.Data[sanitizeKey(id)] = bs
	if err := s.client.UpdateSecret(ctx, secret); err != nil {
		return err
	}
	return err
}
