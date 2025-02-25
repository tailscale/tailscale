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
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
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

	// envCertSecretName is the environment variable for specifying a separate Secret for certificates.
	envCertSecretName = "TS_KUBE_CERT_SECRET"
	// envCertDir is the environment variable for specifying a directory to load certificates from.
	envCertDir = "TS_KUBE_CERT_DIR"
)

// Store is an ipn.StateStore that uses a Kubernetes Secret for persistence.
type Store struct {
	client          kubeclient.Client
	canPatch        bool
	stateSecretName string
	certSecretName  string
	certDir         string

	// memory holds the latest tailscale state. Writes write state to a kube Secret and memory, Reads read from
	// memory.
	memory mem.Store
}

// New returns a new Store that persists to the named Secret.
func New(logf logger.Logf, secretName string) (*Store, error) {
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

	certSecretName := os.Getenv(envCertSecretName)
	if certSecretName != "" {
		logf("kubestore: using separate secret %q for certificates", certSecretName)
		// Also check permissions for cert secret
		_, _, err := c.CheckSecretPermissions(context.Background(), certSecretName)
		if err != nil {
			return nil, fmt.Errorf("checking cert secret permissions: %w", err)
		}
	}

	s := &Store{
		client:          c,
		canPatch:        canPatch,
		stateSecretName: secretName,
		certSecretName:  certSecretName,
		certDir:         os.Getenv(envCertDir),
	}

	// Load latest state from kube Secret if it already exists
	if err := s.loadState(); err != nil && err != ipn.ErrStateNotExist {
		return nil, fmt.Errorf("error loading state from kube Secret: %w", err)
	}

	// If cert directory is specified, load certs into secret
	if s.certDir != "" {
		logf("kubestore: loading certificates from directory %q", s.certDir)
		if err := s.loadCertsFromDir(); err != nil {
			return nil, fmt.Errorf("error loading certs from directory: %w", err)
		}
		logf("kubestore: starting certificate directory watcher")
		go s.watchCertDir(context.Background())
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

	secret, err := s.client.GetSecret(ctx, s.stateSecretName)
	if err != nil {
		if kubeclient.IsNotFoundErr(err) {
			return s.client.CreateSecret(ctx, &kubeapi.Secret{
				TypeMeta: kubeapi.TypeMeta{
					APIVersion: "v1",
					Kind:       "Secret",
				},
				ObjectMeta: kubeapi.ObjectMeta{
					Name: s.stateSecretName,
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
			if err := s.client.JSONPatchResource(ctx, s.stateSecretName, kubeclient.TypeSecrets, m); err != nil {
				return fmt.Errorf("error patching Secret %s with a /data field: %v", s.stateSecretName, err)
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
		if err := s.client.JSONPatchResource(ctx, s.stateSecretName, kubeclient.TypeSecrets, m); err != nil {
			return fmt.Errorf("error patching Secret %s with /data/%s field: %v", s.stateSecretName, sanitizeKey(id), err)
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

	secret, err := s.client.GetSecret(ctx, s.stateSecretName)
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

// WriteTLSCertAndKey atomically writes both the certificate and private key for domain.
func (s *Store) WriteTLSCertAndKey(domain string, cert, key []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	secretName := s.stateSecretName
	if s.certSecretName != "" {
		log.Printf("kubestore: writing certificates for %q to separate cert secret %q", domain, s.certSecretName)
		secretName = s.certSecretName
	}

	secret, err := s.client.GetSecret(ctx, secretName)
	if err != nil {
		if kubeclient.IsNotFoundErr(err) {
			log.Printf("kubestore: creating new secret %q for certificates", secretName)
			return s.client.CreateSecret(ctx, &kubeapi.Secret{
				TypeMeta: kubeapi.TypeMeta{
					APIVersion: "v1",
					Kind:       "Secret",
				},
				ObjectMeta: kubeapi.ObjectMeta{
					Name: secretName,
				},
				Data: map[string][]byte{
					sanitizeKey(ipn.StateKey(domain + ".crt")): cert,
					sanitizeKey(ipn.StateKey(domain + ".key")): key,
				},
			})
		}
		return fmt.Errorf("getting secret %q: %w", secretName, err)
	}

	if s.canPatch {
		if len(secret.Data) == 0 {
			log.Printf("kubestore: initializing empty secret %q with certificates", secretName)
			m := []kubeclient.JSONPatch{
				{
					Op:   "add",
					Path: "/data",
					Value: map[string][]byte{
						sanitizeKey(ipn.StateKey(domain + ".crt")): cert,
						sanitizeKey(ipn.StateKey(domain + ".key")): key,
					},
				},
			}
			return s.client.JSONPatchResource(ctx, secretName, kubeclient.TypeSecrets, m)
		}
		log.Printf("kubestore: patching certificates into secret %q", secretName)
		m := []kubeclient.JSONPatch{
			{
				Op:    "add",
				Path:  "/data/" + sanitizeKey(ipn.StateKey(domain+".crt")),
				Value: cert,
			},
			{
				Op:    "add",
				Path:  "/data/" + sanitizeKey(ipn.StateKey(domain+".key")),
				Value: key,
			},
		}
		return s.client.JSONPatchResource(ctx, secretName, kubeclient.TypeSecrets, m)
	}

	log.Printf("kubestore: updating certificates in secret %q", secretName)
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[sanitizeKey(ipn.StateKey(domain+".crt"))] = cert
	secret.Data[sanitizeKey(ipn.StateKey(domain+".key"))] = key
	return s.client.UpdateSecret(ctx, secret)
}

// loadCertsFromDir reads certificates from the configured directory into memory.
func (s *Store) loadCertsFromDir() error {
	if s.certDir == "" {
		return nil
	}

	entries, err := os.ReadDir(s.certDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".key") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(s.certDir, name))
		if err != nil {
			return fmt.Errorf("reading cert file %q: %w", name, err)
		}

		// Store in memory
		s.memory.WriteState(ipn.StateKey(name), data)
		count++
	}

	log.Printf("kubestore: loaded %d certificate files from %s", count, s.certDir)
	return nil
}

// watchCertDir watches the cert directory for changes and reloads certificates into memory
// when changes are detected. It exits when the context is canceled.
func (s *Store) watchCertDir(ctx context.Context) {
	if s.certDir == "" {
		return
	}

	var tickChan <-chan time.Time
	var eventChan <-chan fsnotify.Event
	if w, err := fsnotify.NewWatcher(); err != nil {
		log.Printf("kubestore: failed to create fsnotify watcher for %q, falling back to timer-only mode: %v", s.certDir, err)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		tickChan = ticker.C
	} else {
		defer w.Close()
		if err := w.Add(s.certDir); err != nil {
			log.Printf("kubestore: failed to add fsnotify watch for %q: %v", s.certDir, err)
			return
		}
		log.Printf("kubestore: watching %q for certificate changes", s.certDir)
		eventChan = w.Events
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickChan:
		case <-eventChan:
			// We can't do any reasonable filtering on the event because of how
			// k8s handles these mounts. So just re-read the directory and
			// update memory if needed.
		}
		if err := s.loadCertsFromDir(); err != nil {
			log.Printf("kubestore: error reloading certs from directory: %v", err)
		}
	}
}
