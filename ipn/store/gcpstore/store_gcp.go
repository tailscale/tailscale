// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gcpstore contains an ipn.StateStore implementation using GCP Secrets Manager.
package gcpstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/googleapi"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/logger"
)

// gcpSecretManagerClient is an interface allowing us to mock the couple of
// API calls we are leveraging with the gcpStore provider
type gcpSecretManagerClient interface {
	AccessSecretVersion(ctx context.Context,
		req *secretmanagerpb.AccessSecretVersionRequest,
		opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)

	CreateSecret(ctx context.Context,
		req *secretmanagerpb.CreateSecretRequest,
		opts ...gax.CallOption) (*secretmanagerpb.Secret, error)

	AddSecretVersion(ctx context.Context,
		req *secretmanagerpb.AddSecretVersionRequest,
		opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)

	DestroySecretVersion(
		ctx context.Context,
		req *secretmanagerpb.DestroySecretVersionRequest,
		opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
}

// gcpStore is a store which leverages GCP secret manager to persist the state
type gcpStore struct {
	smClient gcpSecretManagerClient
	secretID string

	memory mem.Store
}

// New returns a new ipn.StateStore using the GCP secrets manager secret
// given by the secret ID.
func New(_ logger.Logf, secretID string) (ipn.StateStore, error) {
	return newStore(secretID, nil)
}

// newStore is NewStore, but for tests. If client is non-nil, it's
// used instead of making one.
func newStore(secretID string, client gcpSecretManagerClient) (ipn.StateStore, error) {
	s := &gcpStore{
		smClient: client,
		secretID: secretID,
	}

	if s.smClient == nil {
		client, err := secretmanager.NewClient(context.TODO())
		if err != nil {
			return nil, err
		}
		s.smClient = client
	}

	// Hydrate cache with the potentially current state
	if err := s.LoadState(); err != nil {
		return nil, err
	}
	return s, nil
}

// LoadState attempts to read the state from the GCP secret.
func (s *gcpStore) LoadState() error {
	secret, err := s.smClient.AccessSecretVersion(
		context.TODO(),
		&secretmanagerpb.AccessSecretVersionRequest{
			Name: s.secretID + "/versions/latest",
		},
	)

	if err != nil {
		var e *googleapi.Error
		if ok := errors.As(err, &e); ok {
			if e.Code == http.StatusNotFound {
				return s.createState()
			}
		}
		return err
	}

	return s.memory.LoadFromJSON(secret.GetPayload().GetData())
}

func (s *gcpStore) String() string {
	return fmt.Sprintf("gcpStore(%q)", s.secretID)
}

// ReadState implements the Store interface.
func (s *gcpStore) ReadState(id ipn.StateKey) (bs []byte, err error) {
	return s.memory.ReadState(id)
}

// WriteState implements the Store interface.
func (s *gcpStore) WriteState(id ipn.StateKey, bs []byte) (err error) {
	if err = s.memory.WriteState(id, bs); err != nil {
		return
	}
	// Upload new secret version to GCP secret manager.
	return s.persistState()
}

// persistState creates the state for the first time in GCP secret manager.
func (s *gcpStore) createState() error {
	// Lookup secret from user-provided secret ID
	projectID := projectFromSecretID(s.secretID)
	if projectID == "" {
		return fmt.Errorf(`failed to derive project from secret "%s"`, s.secretID)
	}

	// Create new secret in GCP
	_, err := s.smClient.CreateSecret(
		context.TODO(),
		&secretmanagerpb.CreateSecretRequest{
			Parent:   "projects/" + projectID,
			SecretId: s.secretID,
			Secret: &secretmanagerpb.Secret{
				Replication: &secretmanagerpb.Replication{
					Replication: &secretmanagerpb.Replication_Automatic_{},
				},
				Labels: map[string]string{
					"origin": "tailscale",
				},
			},
		},
	)
	if err != nil {
		return err
	}

	// Write first version into secret.
	return s.persistState()
}

// persistState updates the states into GCP secret manager.
func (s *gcpStore) persistState() error {
	// Generate JSON from in-memory cache
	bs, err := s.memory.ExportToJSON()
	if err != nil {
		return err
	}

	// Upload new secret version
	version, err := s.smClient.AddSecretVersion(
		context.TODO(),
		&secretmanagerpb.AddSecretVersionRequest{
			Parent: s.secretID,
			Payload: &secretmanagerpb.SecretPayload{
				Data: bs,
			},
		},
	)
	if err != nil {
		return err
	}

	// Destroy previous secret version
	if versionNumber := versionFromSecretID(version.Name); versionNumber > 1 {
		return s.destroyStateVersion(versionNumber - 1)
	}
	return nil
}

func (s *gcpStore) destroyStateVersion(version int) error {
	_, err := s.smClient.DestroySecretVersion(
		context.TODO(),
		&secretmanagerpb.DestroySecretVersionRequest{
			Name: fmt.Sprintf("%s/versions/%d", s.secretID, version),
		},
	)
	var e *googleapi.Error
	if ok := errors.As(err, &e); ok {
		// It's ok if secret version does not exist or has already been destroyed.
		if e.Code == http.StatusNotFound || e.Code == http.StatusPreconditionFailed {
			return nil
		}
	}
	return err
}

// projectFromSecretID returns the GCP project of a secret ID.
// Returns an empty string on error.
func projectFromSecretID(secretID string) string {
	parts := strings.SplitN(secretID, "/", 3)
	if len(parts) != 3 || parts[0] != "projects" {
		return ""
	}
	return parts[1]
}

// versionStringFromSecretID returns the version string of a secret ID.
// Returns an empty string on error.
func versionStringFromSecretID(secretID string) string {
	parts := strings.SplitN(secretID, "/", 7)
	if len(parts) != 6 || parts[4] != "versions" {
		return ""
	}
	return parts[5]
}

// versionFromSecretID returns the version integer of a secret ID.
// Returns 0 on error.
func versionFromSecretID(secretID string) int {
	version, _ := strconv.Atoi(versionStringFromSecretID(secretID))
	return version
}
