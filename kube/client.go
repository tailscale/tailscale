// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kube provides a client to interact with Kubernetes.
// This package is Tailscale-internal and not meant for external consumption.
// Further, the API should not be considered stable.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tailscale.com/util/multierr"
)

const (
	saPath     = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultURL = "https://kubernetes.default.svc"
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
type Client struct {
	mu          sync.Mutex
	url         string
	ns          string
	client      *http.Client
	token       string
	tokenExpiry time.Time
}

// New returns a new client
func New() (*Client, error) {
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
	return &Client{
		url: defaultURL,
		ns:  string(ns),
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: cp,
				},
			},
		},
	}, nil
}

// SetURL sets the URL to use for the Kubernetes API.
// This is used only for testing.
func (c *Client) SetURL(url string) {
	c.url = url
}

// SetDialer sets the dialer to use when establishing a connection
// to the Kubernetes API server.
func (c *Client) SetDialer(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) {
	c.client.Transport.(*http.Transport).DialContext = dialer
}

func (c *Client) expireToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokenExpiry = time.Now()
}

func (c *Client) getOrRenewToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tk, te := c.token, c.tokenExpiry
	if time.Now().Before(te) {
		return tk, nil
	}

	tkb, err := readFile("token")
	if err != nil {
		return "", err
	}
	c.token = string(tkb)
	c.tokenExpiry = time.Now().Add(30 * time.Minute)
	return c.token, nil
}

func (c *Client) secretURL(name string) string {
	if name == "" {
		return fmt.Sprintf("%s/api/v1/namespaces/%s/secrets", c.url, c.ns)
	}
	return fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", c.url, c.ns, name)
}

func getError(resp *http.Response) error {
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		// These are the only success codes returned by the Kubernetes API.
		// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#http-status-codes
		return nil
	}
	st := &Status{}
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

// doRequest performs an HTTP request to the Kubernetes API.
// If in is not nil, it is expected to be a JSON-encodable object and will be
// sent as the request body.
// If out is not nil, it is expected to be a pointer to an object that can be
// decoded from JSON.
// If the request fails with a 401, the token is expired and a new one is
// requested.
func (c *Client) doRequest(ctx context.Context, method, url string, in, out any, opts ...func(*http.Request)) error {
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
		if st, ok := err.(*Status); ok && st.Code == 401 {
			c.expireToken()
		}
		return err
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) newRequest(ctx context.Context, method, url string, in any) (*http.Request, error) {
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
func (c *Client) GetSecret(ctx context.Context, name string) (*Secret, error) {
	s := &Secret{Data: make(map[string][]byte)}
	if err := c.doRequest(ctx, "GET", c.secretURL(name), nil, s); err != nil {
		return nil, err
	}
	return s, nil
}

// CreateSecret creates a secret in the Kubernetes API.
func (c *Client) CreateSecret(ctx context.Context, s *Secret) error {
	s.Namespace = c.ns
	return c.doRequest(ctx, "POST", c.secretURL(""), s, nil)
}

// UpdateSecret updates a secret in the Kubernetes API.
func (c *Client) UpdateSecret(ctx context.Context, s *Secret) error {
	return c.doRequest(ctx, "PUT", c.secretURL(s.Name), s, nil)
}

// JSONPatch is a JSON patch operation.
// It currently (2023-03-02) only supports the "remove" operation.
//
// https://tools.ietf.org/html/rfc6902
type JSONPatch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// JSONPatchSecret updates a secret in the Kubernetes API using a JSON patch.
// It currently (2023-03-02) only supports the "remove" operation.
func (c *Client) JSONPatchSecret(ctx context.Context, name string, patch []JSONPatch) error {
	for _, p := range patch {
		if p.Op != "remove" && p.Op != "add" {
			panic(fmt.Errorf("unsupported JSON patch operation: %q", p.Op))
		}
	}
	return c.doRequest(ctx, "PATCH", c.secretURL(name), patch, nil, setHeader("Content-Type", "application/json-patch+json"))
}

// StrategicMergePatchSecret updates a secret in the Kubernetes API using a
// strategic merge patch.
// If a fieldManager is provided, it will be used to track the patch.
func (c *Client) StrategicMergePatchSecret(ctx context.Context, name string, s *Secret, fieldManager string) error {
	surl := c.secretURL(name)
	if fieldManager != "" {
		uv := url.Values{
			"fieldManager": {fieldManager},
		}
		surl += "?" + uv.Encode()
	}
	s.Namespace = c.ns
	s.Name = name
	return c.doRequest(ctx, "PATCH", surl, s, nil, setHeader("Content-Type", "application/strategic-merge-patch+json"))
}

// CheckSecretPermissions checks the secret access permissions of the current
// pod. It returns an error if the basic permissions tailscale needs are
// missing, and reports whether the patch permission is additionally present.
//
// Errors encountered during the access checking process are logged, but ignored
// so that the pod tries to fail alive if the permissions exist and there's just
// something wrong with SelfSubjectAccessReviews. There shouldn't be, pods
// should always be able to use SSARs to assess their own permissions, but since
// we didn't use to check permissions this way we'll be cautious in case some
// old version of k8s deviates from the current behavior.
func (c *Client) CheckSecretPermissions(ctx context.Context, secretName string) (canPatch bool, err error) {
	var errs []error
	for _, verb := range []string{"get", "update"} {
		ok, err := c.checkPermission(ctx, verb, secretName)
		if err != nil {
			log.Printf("error checking %s permission on secret %s: %v", verb, secretName, err)
		} else if !ok {
			errs = append(errs, fmt.Errorf("missing %s permission on secret %q", verb, secretName))
		}
	}
	if len(errs) > 0 {
		return false, multierr.New(errs...)
	}
	ok, err := c.checkPermission(ctx, "patch", secretName)
	if err != nil {
		log.Printf("error checking patch permission on secret %s: %v", secretName, err)
		return false, nil
	}
	return ok, nil
}

// checkPermission reports whether the current pod has permission to use the
// given verb (e.g. get, update, patch) on secretName.
func (c *Client) checkPermission(ctx context.Context, verb, secretName string) (bool, error) {
	sar := map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"spec": map[string]any{
			"resourceAttributes": map[string]any{
				"namespace": c.ns,
				"verb":      verb,
				"resource":  "secrets",
				"name":      secretName,
			},
		},
	}
	var res struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	url := c.url + "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
	if err := c.doRequest(ctx, "POST", url, sar, &res); err != nil {
		return false, err
	}
	return res.Status.Allowed, nil
}
