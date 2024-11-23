// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kubestore contains an ipn.StateStore implementation using Kubernetes Secrets.
package kubestore

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/types/logger"
)

const (
	// timeout is the timeout for a single state update that includes calls to the API server to write or read a
	// state Secret and emit an Event.
	timeout = 30 * time.Second

	reasonTailscaleStateUpdated      = "TailscaledStateUpdated"
	reasonTailscaleStateLoaded       = "TailscaleStateLoaded"
	reasonTailscaleStateUpdateFailed = "TailscaleStateUpdateFailed"
	reasonTailscaleStateLoadFailed   = "TailscaleStateLoadFailed"
	eventTypeWarning                 = "Warning"
	eventTypeNormal                  = "Normal"
)

// Store is an ipn.StateStore that uses a Kubernetes Secret for persistence.
type Store struct {
	client     kubeclient.Client
	canPatch   bool
	secretName string

	// memory holds the latest tailscale state. Writes write state to a kube Secret and memory, Reads read from
	// memory.
	memory mem.Store
}

// New returns a new Store that persists to the named Secret.
func New(_ logger.Logf, secretName string) (*Store, error) {
	c, err := kubeclient.New("tailscale-state-store")
	if err != nil {
		return nil, err
	}
	if os.Getenv("TS_KUBERNETES_READ_API_SERVER_ADDRESS_FROM_ENV") == "true" {
		// Derive the API server address from the environment variables
		c.SetURL(fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")))
	}
	canPatch, _, err := c.CheckSecretPermissions(context.Background(), secretName)
	if err != nil {
		return nil, err
	}
	s := &Store{
		client:     c,
		canPatch:   canPatch,
		secretName: secretName,
	}
	// Load latest state from kube Secret if it already exists.
	if err := s.loadState(); err != nil && err != ipn.ErrStateNotExist {
		return nil, fmt.Errorf("error loading state from kube Secret: %w", err)
	}
	return s, nil
}

func (s *Store) SetDialer(d func(ctx context.Context, network, address string) (net.Conn, error)) {
	s.client.SetDialer(d)
}

func (s *Store) String() string { return "kube.Store" }

// ReadState implements the StateStore interface.
func (s *Store) ReadState(id ipn.StateKey) ([]byte, error) {
	return s.memory.ReadState(ipn.StateKey(sanitizeKey(id)))
}

// WriteState implements the StateStore interface.
func (s *Store) WriteState(id ipn.StateKey, bs []byte) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer func() {
		if err == nil {
			s.memory.WriteState(ipn.StateKey(sanitizeKey(id)), bs)
		}
		if err != nil {
			if err := s.client.Event(ctx, eventTypeWarning, reasonTailscaleStateUpdateFailed, err.Error()); err != nil {
				log.Printf("kubestore: error creating tailscaled state update Event: %v", err)
			}
		} else {
			if err := s.client.Event(ctx, eventTypeNormal, reasonTailscaleStateUpdated, "Successfully updated tailscaled state Secret"); err != nil {
				log.Printf("kubestore: error creating tailscaled state Event: %v", err)
			}
		}
		cancel()
	}()

	secret, err := s.client.GetSecret(ctx, s.secretName)
	if err != nil {
		if kubeclient.IsNotFoundErr(err) {
			return s.client.CreateSecret(ctx, &kubeapi.Secret{
				TypeMeta: kubeapi.TypeMeta{
					APIVersion: "v1",
					Kind:       "Secret",
				},
				ObjectMeta: kubeapi.ObjectMeta{
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
			m := []kubeclient.JSONPatch{
				{
					Op:    "add",
					Path:  "/data",
					Value: map[string][]byte{sanitizeKey(id): bs},
				},
			}
			if err := s.client.JSONPatchResource(ctx, s.secretName, kubeclient.TypeSecrets, m); err != nil {
				return fmt.Errorf("error patching Secret %s with a /data field: %v", s.secretName, err)
			}
			return nil
		}
		m := []kubeclient.JSONPatch{
			{
				Op:    "add",
				Path:  "/data/" + sanitizeKey(id),
				Value: bs,
			},
		}
		if err := s.client.JSONPatchResource(ctx, s.secretName, kubeclient.TypeSecrets, m); err != nil {
			return fmt.Errorf("error patching Secret %s with /data/%s field: %v", s.secretName, sanitizeKey(id), err)
		}
		return nil
	}
	secret.Data[sanitizeKey(id)] = bs
	if err := s.client.UpdateSecret(ctx, secret); err != nil {
		return err
	}
	return err
}

func (s *Store) loadState() (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	secret, err := s.client.GetSecret(ctx, s.secretName)
	if err != nil {
		if st, ok := err.(*kubeapi.Status); ok && st.Code == 404 {
			return ipn.ErrStateNotExist
		}
		if err := s.client.Event(ctx, eventTypeWarning, reasonTailscaleStateLoadFailed, err.Error()); err != nil {
			log.Printf("kubestore: error creating Event: %v", err)
		}
		return err
	}
	if err := s.client.Event(ctx, eventTypeNormal, reasonTailscaleStateLoaded, "Successfully loaded tailscaled state from Secret"); err != nil {
		log.Printf("kubestore: error creating Event: %v", err)
	}
	s.memory.LoadFromMap(secret.Data)
	return nil
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
