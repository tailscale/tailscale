// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kubeclient provides a client to interact with Kubernetes.
// This package is Tailscale-internal and not meant for external consumption.
// Further, the API should not be considered stable.
// Client is split into a separate package for consumption of
// non-Kubernetes shared libraries and binaries. Be mindful of not increasing
// dependency size for those consumers when adding anything new here.
package kubeclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tailscale.com/kube/kubeapi"
	"tailscale.com/tstime"
)

const (
	saPath     = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultURL = "https://kubernetes.default.svc"

	TypeSecrets = "secrets"
	typeEvents  = "events"
)

// rootPathForTests is set by tests to override the root path to the
// service account directory.
var rootPathForTests string

// SetRootPathForTesting sets the path to the service account directory.
func SetRootPathForTesting(p string) {
	rootPathForTests = p
}

func readFile(n string) ([]byte, error) {
	if rootPathForTests != "" {
		return os.ReadFile(filepath.Join(rootPathForTests, saPath, n))
	}
	return os.ReadFile(filepath.Join(saPath, n))
}

// Client handles connections to Kubernetes.
// It expects to be run inside a cluster.
type Client interface {
	GetSecret(context.Context, string) (*kubeapi.Secret, error)
	ListSecrets(context.Context, map[string]string) (*kubeapi.SecretList, error)
	UpdateSecret(context.Context, *kubeapi.Secret) error
	CreateSecret(context.Context, *kubeapi.Secret) error
	// Event attempts to ensure an event with the specified options associated with the Pod in which we are
	// currently running. This is best effort - if the client is not able to create events, this operation will be a
	// no-op. If there is already an Event with the given reason for the current Pod, it will get updated (only
	// count and timestamp are expected to change), else a new event will be created.
	Event(_ context.Context, typ, reason, msg string) error
	StrategicMergePatchSecret(context.Context, string, *kubeapi.Secret, string) error
	JSONPatchResource(_ context.Context, resourceName string, resourceType string, patches []JSONPatch) error
	CheckSecretPermissions(context.Context, string) (bool, bool, error)
	SetDialer(dialer func(context.Context, string, string) (net.Conn, error))
	SetURL(string)
}

type client struct {
	mu          sync.Mutex
	name        string
	url         string
	podName     string
	podUID      string
	ns          string // Pod namespace
	client      *http.Client
	token       string
	tokenExpiry time.Time
	cl          tstime.Clock
	// hasEventsPerms is true if client can emit Events for the Pod in which it runs. If it is set to false any
	// calls to Events() will be a no-op.
	hasEventsPerms bool
	// kubeAPIRequest sends a request to the kube API server. It can set to a fake in tests.
	kubeAPIRequest kubeAPIRequestFunc
}

// New returns a new client
func New(name string) (Client, error) {
	ns, err := readFile("namespace")
	if err != nil {
		return nil, err
	}
	caCert, err := readFile("ca.crt")
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	if ok := cp.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("kube: error in creating root cert pool")
	}
	c := &client{
		url:  defaultURL,
		ns:   string(ns),
		name: name,
		cl:   tstime.DefaultClock{},
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: cp,
				},
			},
		},
	}
	c.kubeAPIRequest = newKubeAPIRequest(c)
	c.setEventPerms()
	return c, nil
}

// SetURL sets the URL to use for the Kubernetes API.
// This is used only for testing.
func (c *client) SetURL(url string) {
	c.url = url
}

// SetDialer sets the dialer to use when establishing a connection
// to the Kubernetes API server.
func (c *client) SetDialer(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) {
	c.client.Transport.(*http.Transport).DialContext = dialer
}

func (c *client) expireToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokenExpiry = c.cl.Now()
}

func (c *client) getOrRenewToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tk, te := c.token, c.tokenExpiry
	if c.cl.Now().Before(te) {
		return tk, nil
	}

	tkb, err := readFile("token")
	if err != nil {
		return "", err
	}
	c.token = string(tkb)
	c.tokenExpiry = c.cl.Now().Add(30 * time.Minute)
	return c.token, nil
}

func getError(resp *http.Response) error {
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		// These are the only success codes returned by the Kubernetes API.
		// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#http-status-codes
		return nil
	}
	st := &kubeapi.Status{}
	if err := json.NewDecoder(resp.Body).Decode(st); err != nil {
		return err
	}
	return st
}

func setHeader(key, value string) func(*http.Request) {
	return func(req *http.Request) {
		req.Header.Set(key, value)
	}
}

type kubeAPIRequestFunc func(ctx context.Context, method, url string, in, out any, opts ...func(*http.Request)) error

// newKubeAPIRequest returns a function that can perform an HTTP request to the Kubernetes API.
func newKubeAPIRequest(c *client) kubeAPIRequestFunc {
	// If in is not nil, it is expected to be a JSON-encodable object and will be
	// sent as the request body.
	// If out is not nil, it is expected to be a pointer to an object that can be
	// decoded from JSON.
	// If the request fails with a 401, the token is expired and a new one is
	// requested.
	f := func(ctx context.Context, method, url string, in, out any, opts ...func(*http.Request)) error {
		req, err := c.newRequest(ctx, method, url, in)
		if err != nil {
			return err
		}
		for _, opt := range opts {
			opt(req)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := getError(resp); err != nil {
			if st, ok := err.(*kubeapi.Status); ok && st.Code == 401 {
				c.expireToken()
			}
			return err
		}
		if out != nil {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}
	return f
}

func (c *client) newRequest(ctx context.Context, method, url string, in any) (*http.Request, error) {
	tk, err := c.getOrRenewToken()
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if in != nil {
		switch in := in.(type) {
		case []byte:
			body = bytes.NewReader(in)
		default:
			var b bytes.Buffer
			if err := json.NewEncoder(&b).Encode(in); err != nil {
				return nil, err
			}
			body = &b
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Add("Content-Type", "application/json")
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+tk)
	return req, nil
}

// GetSecret fetches the secret from the Kubernetes API.
func (c *client) GetSecret(ctx context.Context, name string) (*kubeapi.Secret, error) {
	s := &kubeapi.Secret{Data: make(map[string][]byte)}
	if err := c.kubeAPIRequest(ctx, "GET", c.resourceURL(name, TypeSecrets, ""), nil, s); err != nil {
		return nil, err
	}
	return s, nil
}

// ListSecrets fetches the secret from the Kubernetes API.
func (c *client) ListSecrets(ctx context.Context, selector map[string]string) (*kubeapi.SecretList, error) {
	sl := new(kubeapi.SecretList)
	s := make([]string, 0, len(selector))
	for key, val := range selector {
		s = append(s, key+"="+url.QueryEscape(val))
	}
	ss := strings.Join(s, ",")
	if err := c.kubeAPIRequest(ctx, "GET", c.resourceURL("", TypeSecrets, ss), nil, sl); err != nil {
		return nil, err
	}
	return sl, nil
}

// CreateSecret creates a secret in the Kubernetes API.
func (c *client) CreateSecret(ctx context.Context, s *kubeapi.Secret) error {
	s.Namespace = c.ns
	return c.kubeAPIRequest(ctx, "POST", c.resourceURL("", TypeSecrets, ""), s, nil)
}

// UpdateSecret updates a secret in the Kubernetes API.
func (c *client) UpdateSecret(ctx context.Context, s *kubeapi.Secret) error {
	return c.kubeAPIRequest(ctx, "PUT", c.resourceURL(s.Name, TypeSecrets, ""), s, nil)
}

// JSONPatch is a JSON patch operation.
// It currently (2024-11-15) only supports "add", "remove" and "replace" operations.
//
// https://tools.ietf.org/html/rfc6902
type JSONPatch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// JSONPatchResource updates a resource in the Kubernetes API using a JSON patch.
// It currently (2024-11-15) only supports "add", "remove" and "replace" operations.
func (c *client) JSONPatchResource(ctx context.Context, name, typ string, patches []JSONPatch) error {
	for _, p := range patches {
		if p.Op != "remove" && p.Op != "add" && p.Op != "replace" {
			return fmt.Errorf("unsupported JSON patch operation: %q", p.Op)
		}
	}
	return c.kubeAPIRequest(ctx, "PATCH", c.resourceURL(name, typ, ""), patches, nil, setHeader("Content-Type", "application/json-patch+json"))
}

// StrategicMergePatchSecret updates a secret in the Kubernetes API using a
// strategic merge patch.
// If a fieldManager is provided, it will be used to track the patch.
func (c *client) StrategicMergePatchSecret(ctx context.Context, name string, s *kubeapi.Secret, fieldManager string) error {
	surl := c.resourceURL(name, TypeSecrets, "")
	if fieldManager != "" {
		uv := url.Values{
			"fieldManager": {fieldManager},
		}
		surl += "?" + uv.Encode()
	}
	s.Namespace = c.ns
	s.Name = name
	return c.kubeAPIRequest(ctx, "PATCH", surl, s, nil, setHeader("Content-Type", "application/strategic-merge-patch+json"))
}

// Event tries to ensure an Event associated with the Pod in which we are running. It is best effort - the event will be
// created if the kube client on startup was able to determine the name and UID of this Pod from POD_NAME,POD_UID env
// vars and if permissions check for event creation succeeded. Events are keyed on opts.Reason- if an Event for the
// current Pod with that reason already exists, its count and first timestamp will be updated, else a new Event will be
// created.
func (c *client) Event(ctx context.Context, typ, reason, msg string) error {
	if !c.hasEventsPerms {
		return nil
	}
	name := c.nameForEvent(reason)
	ev, err := c.getEvent(ctx, name)
	now := c.cl.Now()
	if err != nil {
		if !IsNotFoundErr(err) {
			return err
		}
		// Event not found - create it
		ev := kubeapi.Event{
			ObjectMeta: kubeapi.ObjectMeta{
				Name:      name,
				Namespace: c.ns,
			},
			Type:    typ,
			Reason:  reason,
			Message: msg,
			Source: kubeapi.EventSource{
				Component: c.name,
			},
			InvolvedObject: kubeapi.ObjectReference{
				Name:       c.podName,
				Namespace:  c.ns,
				UID:        c.podUID,
				Kind:       "Pod",
				APIVersion: "v1",
			},

			FirstTimestamp: now,
			LastTimestamp:  now,
			Count:          1,
		}
		return c.kubeAPIRequest(ctx, "POST", c.resourceURL("", typeEvents, ""), &ev, nil)
	}
	// If the Event already exists, we patch its count and last timestamp. This ensures that when users run 'kubectl
	// describe pod...', they see the event just once (but with a message of how many times it has appeared over
	// last timestamp - first timestamp period of time).
	count := ev.Count + 1
	countPatch := JSONPatch{
		Op:    "replace",
		Value: count,
		Path:  "/count",
	}
	tsPatch := JSONPatch{
		Op:    "replace",
		Value: now,
		Path:  "/lastTimestamp",
	}
	return c.JSONPatchResource(ctx, name, typeEvents, []JSONPatch{countPatch, tsPatch})
}

// CheckSecretPermissions checks the secret access permissions of the current
// pod. It returns an error if the basic permissions tailscale needs are
// missing, and reports whether the patch and create permissions are additionally present.
//
// Errors encountered during the access checking process are logged, but ignored
// so that the pod tries to fail alive if the permissions exist and there's just
// something wrong with SelfSubjectAccessReviews. There shouldn't be, pods
// should always be able to use SSARs to assess their own permissions, but since
// we didn't use to check permissions this way we'll be cautious in case some
// old version of k8s deviates from the current behavior.
func (c *client) CheckSecretPermissions(ctx context.Context, secretName string) (canPatch, canCreate bool, err error) {
	var errs []error
	for _, verb := range []string{"get", "update"} {
		ok, err := c.checkPermission(ctx, verb, TypeSecrets, secretName)
		if err != nil {
			log.Printf("error checking %s permission on secret %s: %v", verb, secretName, err)
		} else if !ok {
			errs = append(errs, fmt.Errorf("missing %s permission on secret %q", verb, secretName))
		}
	}
	if len(errs) > 0 {
		return false, false, errors.Join(errs...)
	}
	canPatch, err = c.checkPermission(ctx, "patch", TypeSecrets, secretName)
	if err != nil {
		log.Printf("error checking patch permission on secret %s: %v", secretName, err)
		return false, false, nil
	}
	canCreate, err = c.checkPermission(ctx, "create", TypeSecrets, secretName)
	if err != nil {
		log.Printf("error checking create permission on secret %s: %v", secretName, err)
		return false, false, nil
	}
	return canPatch, canCreate, nil
}

func IsNotFoundErr(err error) bool {
	if st, ok := err.(*kubeapi.Status); ok && st.Code == 404 {
		return true
	}
	return false
}

// setEventPerms checks whether this client will be able to write tailscaled Events to its Pod and updates the state
// accordingly. If it determines that the client can not write Events, any subsequent calls to client.Event will be a
// no-op.
func (c *client) setEventPerms() {
	name := os.Getenv("POD_NAME")
	uid := os.Getenv("POD_UID")
	hasPerms := false
	defer func() {
		c.podName = name
		c.podUID = uid
		c.hasEventsPerms = hasPerms
		if !hasPerms {
			log.Printf(`kubeclient: this client is not able to write tailscaled Events to the Pod in which it is running.
			To help with future debugging you can make it able write Events by giving it get,create,patch permissions for Events in the Pod namespace
			and setting POD_NAME, POD_UID env vars for the Pod.`)
		}
	}()
	if name == "" || uid == "" {
		return
	}
	for _, verb := range []string{"get", "create", "patch"} {
		can, err := c.checkPermission(context.Background(), verb, typeEvents, "")
		if err != nil {
			log.Printf("kubeclient: error checking Events permissions: %v", err)
			return
		}
		if !can {
			return
		}
	}
	hasPerms = true
	return
}

// checkPermission reports whether the current pod has permission to use the given verb (e.g. get, update, patch,
// create) on the given resource type. If name is not an empty string, will check the check will be for resource with
// the given name only.
func (c *client) checkPermission(ctx context.Context, verb, typ, name string) (bool, error) {
	ra := map[string]any{
		"namespace": c.ns,
		"verb":      verb,
		"resource":  typ,
	}
	if name != "" {
		ra["name"] = name
	}
	sar := map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"spec": map[string]any{
			"resourceAttributes": ra,
		},
	}
	var res struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	url := c.url + "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
	if err := c.kubeAPIRequest(ctx, "POST", url, sar, &res); err != nil {
		return false, err
	}
	return res.Status.Allowed, nil
}

// resourceURL returns a URL that can be used to interact with the given resource type and, if name is not empty string,
// the named resource of that type.
// Note that this only works for core/v1 resource types.
func (c *client) resourceURL(name, typ, sel string) string {
	if name == "" {
		url := fmt.Sprintf("%s/api/v1/namespaces/%s/%s", c.url, c.ns, typ)
		if sel != "" {
			url += "?labelSelector=" + sel
		}
		return url
	}
	return fmt.Sprintf("%s/api/v1/namespaces/%s/%s/%s", c.url, c.ns, typ, name)
}

// nameForEvent returns a name for the Event that uniquely identifies Event with that reason for the current Pod.
func (c *client) nameForEvent(reason string) string {
	return fmt.Sprintf("%s.%s.%s", c.podName, c.podUID, strings.ToLower(reason))
}

// getEvent fetches the event from the Kubernetes API.
func (c *client) getEvent(ctx context.Context, name string) (*kubeapi.Event, error) {
	e := &kubeapi.Event{}
	if err := c.kubeAPIRequest(ctx, "GET", c.resourceURL(name, typeEvents, ""), nil, e); err != nil {
		return nil, err
	}
	return e, nil
}
