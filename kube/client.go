// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	saPath     = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultURL = "https://kubernetes.default.svc"
)

func readFile(n string) ([]byte, error) {
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

func (c *Client) doRequest(ctx context.Context, method, url string, in, out any) error {
	tk, err := c.getOrRenewToken()
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(in); err != nil {
			return err
		}
		body = &b
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Add("Content-Type", "application/json")
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+tk)
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
