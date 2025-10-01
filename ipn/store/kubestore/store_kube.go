// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kubestore contains an ipn.StateStore implementation using Kubernetes Secrets.
package kubestore

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
)

func init() {
	store.Register("kube:", func(logf logger.Logf, path string) (ipn.StateStore, error) {
		secretName := strings.TrimPrefix(path, "kube:")
		return New(logf, secretName)
	})
}

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

	keyTLSCert = "tls.crt"
	keyTLSKey  = "tls.key"
)

// Store is an ipn.StateStore that uses a Kubernetes Secret for persistence.
type Store struct {
	client        kubeclient.Client
	canPatch      bool
	secretName    string // state Secret
	certShareMode string // 'ro', 'rw', or empty
	podName       string

	// memory holds the latest tailscale state. Writes write state to a kube
	// Secret and memory, Reads read from memory.
	memory mem.Store
}

// New returns a new Store that persists state to Kubernets Secret(s).
// Tailscale state is stored in a Secret named by the secretName parameter.
// TLS certs are stored and retrieved from state Secret or separate Secrets
// named after TLS endpoints if running in cert share mode.
func New(logf logger.Logf, secretName string) (*Store, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}
	return newWithClient(logf, c, secretName)
}

func newClient() (kubeclient.Client, error) {
	c, err := kubeclient.New("tailscale-state-store")
	if err != nil {
		return nil, err
	}
	if os.Getenv("TS_KUBERNETES_READ_API_SERVER_ADDRESS_FROM_ENV") == "true" {
		// Derive the API server address from the environment variables
		c.SetURL(fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")))
	}
	return c, nil
}

func newWithClient(logf logger.Logf, c kubeclient.Client, secretName string) (*Store, error) {
	canPatch, _, err := c.CheckSecretPermissions(context.Background(), secretName)
	if err != nil {
		return nil, err
	}
	s := &Store{
		client:     c,
		canPatch:   canPatch,
		secretName: secretName,
		podName:    os.Getenv("POD_NAME"),
	}
	if envknob.IsCertShareReadWriteMode() {
		s.certShareMode = "rw"
	} else if envknob.IsCertShareReadOnlyMode() {
		s.certShareMode = "ro"
	}

	// Load latest state from kube Secret if it already exists.
	if err := s.loadState(); err != nil && err != ipn.ErrStateNotExist {
		return nil, fmt.Errorf("error loading state from kube Secret: %w", err)
	}
	// If we are in cert share mode, pre-load existing shared certs.
	if s.certShareMode == "rw" || s.certShareMode == "ro" {
		sel := s.certSecretSelector()
		if err := s.loadCerts(context.Background(), sel); err != nil {
			// We will attempt to again retrieve the certs from Secrets when a request for an HTTPS endpoint
			// is received.
			log.Printf("[unexpected] error loading TLS certs: %v", err)
		}
	}
	if s.certShareMode == "ro" {
		go s.runCertReload(context.Background(), logf)
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
	defer func() {
		if err == nil {
			s.memory.WriteState(ipn.StateKey(sanitizeKey(id)), bs)
		}
	}()
	return s.updateSecret(map[string][]byte{string(id): bs}, s.secretName)
}

// WriteTLSCertAndKey writes a TLS cert and key to domain.crt, domain.key fields
// of a Tailscale Kubernetes node's state Secret.
func (s *Store) WriteTLSCertAndKey(domain string, cert, key []byte) (err error) {
	if s.certShareMode == "ro" {
		log.Printf("[unexpected] TLS cert and key write in read-only mode")
	}
	if err := dnsname.ValidHostname(domain); err != nil {
		return fmt.Errorf("invalid domain name %q: %w", domain, err)
	}
	secretName := s.secretName
	data := map[string][]byte{
		domain + ".crt": cert,
		domain + ".key": key,
	}
	// If we run in cert share mode, cert and key for a DNS name are written
	// to a separate Secret.
	if s.certShareMode == "rw" {
		secretName = domain
		data = map[string][]byte{
			keyTLSCert: cert,
			keyTLSKey:  key,
		}
	}
	if err := s.updateSecret(data, secretName); err != nil {
		return fmt.Errorf("error writing TLS cert and key to Secret: %w", err)
	}
	// TODO(irbekrm): certs for write replicas are currently not
	// written to memory to avoid out of sync memory state after
	// Ingress resources have been recreated.  This means that TLS
	// certs for write replicas are retrieved from the Secret on
	// each HTTPS request.  This is a temporary solution till we
	// implement a Secret watch.
	if s.certShareMode != "rw" {
		s.memory.WriteState(ipn.StateKey(domain+".crt"), cert)
		s.memory.WriteState(ipn.StateKey(domain+".key"), key)
	}
	return nil
}

// ReadTLSCertAndKey reads a TLS cert and key from memory or from a
// domain-specific Secret. It first checks the in-memory store, if not found in
// memory and running cert store in read-only mode, looks up a Secret.
// Note that write replicas of HA Ingress always retrieve TLS certs from Secrets.
func (s *Store) ReadTLSCertAndKey(domain string) (cert, key []byte, err error) {
	if err := dnsname.ValidHostname(domain); err != nil {
		return nil, nil, fmt.Errorf("invalid domain name %q: %w", domain, err)
	}
	certKey := domain + ".crt"
	keyKey := domain + ".key"
	cert, err = s.memory.ReadState(ipn.StateKey(certKey))
	if err == nil {
		key, err = s.memory.ReadState(ipn.StateKey(keyKey))
		if err == nil {
			return cert, key, nil
		}
	}
	if s.certShareMode == "" {
		return nil, nil, ipn.ErrStateNotExist
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	secret, err := s.client.GetSecret(ctx, domain)
	if err != nil {
		if kubeclient.IsNotFoundErr(err) {
			// TODO(irbekrm): we should return a more specific error
			// that wraps ipn.ErrStateNotExist here.
			return nil, nil, ipn.ErrStateNotExist
		}
		st, ok := err.(*kubeapi.Status)
		if ok && st.Code == http.StatusForbidden && (s.certShareMode == "ro" || s.certShareMode == "rw") {
			// In cert share mode, we read from a dedicated Secret per domain.
			// To get here, we already had a cache miss from our in-memory
			// store. For write replicas, that means it wasn't available on
			// start and it wasn't written since. For read replicas, that means
			// it wasn't available on start and it hasn't been reloaded in the
			// background. So getting a "forbidden" error is an expected
			// "not found" case where we've been asked for a cert we don't
			// expect to issue, and so the forbidden error reflects that the
			// operator didn't assign permission for a Secret for that domain.
			//
			// This code path gets triggered by the admin UI's machine page,
			// which queries for the node's own TLS cert existing via the
			// "tls-cert-status" c2n API.
			return nil, nil, ipn.ErrStateNotExist
		}
		return nil, nil, fmt.Errorf("getting TLS Secret %q: %w", domain, err)
	}
	cert = secret.Data[keyTLSCert]
	key = secret.Data[keyTLSKey]
	if len(cert) == 0 || len(key) == 0 {
		return nil, nil, ipn.ErrStateNotExist
	}
	// TODO(irbekrm): a read between these two separate writes would
	// get a mismatched cert and key.  Allow writing both cert and
	// key to the memory store in a single, lock-protected operation.
	//
	// TODO(irbekrm): currently certs for write replicas of HA Ingress get
	// retrieved from the cluster Secret on each HTTPS request to avoid a
	// situation when after Ingress recreation stale certs are read from
	// memory.
	// Fix this by watching Secrets to ensure that memory store gets updated
	// when Secrets are deleted.
	if s.certShareMode == "ro" {
		s.memory.WriteState(ipn.StateKey(certKey), cert)
		s.memory.WriteState(ipn.StateKey(keyKey), key)
	}
	return cert, key, nil
}

func (s *Store) updateSecret(data map[string][]byte, secretName string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer func() {
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
	secret, err := s.client.GetSecret(ctx, secretName)
	if err != nil {
		// If the Secret does not exist, create it with the required data.
		if kubeclient.IsNotFoundErr(err) && s.canCreateSecret(secretName) {
			return s.client.CreateSecret(ctx, &kubeapi.Secret{
				TypeMeta: kubeapi.TypeMeta{
					APIVersion: "v1",
					Kind:       "Secret",
				},
				ObjectMeta: kubeapi.ObjectMeta{
					Name: secretName,
				},
				Data: func(m map[string][]byte) map[string][]byte {
					d := make(map[string][]byte, len(m))
					for key, val := range m {
						d[sanitizeKey(key)] = val
					}
					return d
				}(data),
			})
		}
		return fmt.Errorf("error getting Secret %s: %w", secretName, err)
	}
	if s.canPatchSecret(secretName) {
		var m []kubeclient.JSONPatch
		// If the user has pre-created a Secret with no data, we need to ensure the top level /data field.
		if len(secret.Data) == 0 {
			m = []kubeclient.JSONPatch{
				{
					Op:   "add",
					Path: "/data",
					Value: func(m map[string][]byte) map[string][]byte {
						d := make(map[string][]byte, len(m))
						for key, val := range m {
							d[sanitizeKey(key)] = val
						}
						return d
					}(data),
				},
			}
			// If the Secret has data, patch it with the new data.
		} else {
			for key, val := range data {
				m = append(m, kubeclient.JSONPatch{
					Op:    "add",
					Path:  "/data/" + sanitizeKey(key),
					Value: val,
				})
			}
		}
		if err := s.client.JSONPatchResource(ctx, secretName, kubeclient.TypeSecrets, m); err != nil {
			return fmt.Errorf("error patching Secret %s: %w", secretName, err)
		}
		return nil
	}
	// No patch permissions, use UPDATE instead.
	for key, val := range data {
		mak.Set(&secret.Data, sanitizeKey(key), val)
	}
	if err := s.client.UpdateSecret(ctx, secret); err != nil {
		return fmt.Errorf("error updating Secret %s: %w", s.secretName, err)
	}
	return nil
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

// runCertReload relists and reloads all TLS certs for endpoints shared by this
// node from Secrets other than the state Secret to ensure that renewed certs get eventually loaded.
// It is not critical to reload a cert immediately after
// renewal, so a daily check is acceptable.
// Currently (3/2025) this is only used for the shared HA Ingress certs on 'read' replicas.
// Note that if shared certs are not found in memory on an HTTPS request, we
// do a Secret lookup, so this mechanism does not need to ensure that newly
// added Ingresses' certs get loaded.
func (s *Store) runCertReload(ctx context.Context, logf logger.Logf) {
	ticker := time.NewTicker(time.Hour * 24)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sel := s.certSecretSelector()
			if err := s.loadCerts(ctx, sel); err != nil {
				logf("[unexpected] error reloading TLS certs: %v", err)
			}
		}
	}
}

// loadCerts lists all Secrets matching the provided selector and loads TLS
// certs and keys from those.
func (s *Store) loadCerts(ctx context.Context, sel map[string]string) error {
	ss, err := s.client.ListSecrets(ctx, sel)
	if err != nil {
		return fmt.Errorf("error listing TLS Secrets: %w", err)
	}
	for _, secret := range ss.Items {
		if !hasTLSData(&secret) {
			continue
		}
		// Only load secrets that have valid domain names (ending in .ts.net)
		if !strings.HasSuffix(secret.Name, ".ts.net") {
			continue
		}
		s.memory.WriteState(ipn.StateKey(secret.Name)+".crt", secret.Data[keyTLSCert])
		s.memory.WriteState(ipn.StateKey(secret.Name)+".key", secret.Data[keyTLSKey])
	}
	return nil
}

// canCreateSecret returns true if this node should be allowed to create the given
// Secret in its namespace.
func (s *Store) canCreateSecret(secret string) bool {
	// Only allow creating the state Secret (and not TLS Secrets).
	return secret == s.secretName
}

// canPatchSecret returns true if this node should be allowed to patch the given
// Secret.
func (s *Store) canPatchSecret(secret string) bool {
	// For backwards compatibility reasons, setups where the proxies are not
	// given PATCH permissions for state Secrets are allowed. For TLS
	// Secrets, we should always have PATCH permissions.
	if secret == s.secretName {
		return s.canPatch
	}
	return true
}

// certSecretSelector returns a label selector that can be used to list all
// Secrets that aren't Tailscale state Secrets and contain TLS certificates for
// HTTPS endpoints that this node serves.
// Currently (7/2025) this only applies to the Kubernetes Operator's ProxyGroup
// when spec.Type is "ingress" or "kube-apiserver".
func (s *Store) certSecretSelector() map[string]string {
	if s.podName == "" {
		return map[string]string{}
	}
	p := strings.LastIndex(s.podName, "-")
	if p == -1 {
		return map[string]string{}
	}
	pgName := s.podName[:p]
	return map[string]string{
		kubetypes.LabelSecretType:   kubetypes.LabelSecretTypeCerts,
		kubetypes.LabelManaged:      "true",
		"tailscale.com/proxy-group": pgName,
	}
}

// hasTLSData returns true if the provided Secret contains non-empty TLS cert and key.
func hasTLSData(s *kubeapi.Secret) bool {
	return len(s.Data[keyTLSCert]) != 0 && len(s.Data[keyTLSKey]) != 0
}

// sanitizeKey converts any value that can be converted to a string into a valid Kubernetes Secret key.
// Valid characters are alphanumeric, -, _, and .
// https://kubernetes.io/docs/concepts/configuration/secret/#restriction-names-data.
func sanitizeKey[T ~string](k T) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, string(k))
}
