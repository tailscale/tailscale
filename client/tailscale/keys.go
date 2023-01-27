// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Key represents a Tailscale API or auth key.
type Key struct {
	ID           string          `json:"id"`
	Created      time.Time       `json:"created"`
	Expires      time.Time       `json:"expires"`
	Capabilities KeyCapabilities `json:"capabilities"`
}

// KeyCapabilities are the capabilities of a Key.
type KeyCapabilities struct {
	Devices KeyDeviceCapabilities `json:"devices,omitempty"`
}

// KeyDeviceCapabilities are the device-related capabilities of a Key.
type KeyDeviceCapabilities struct {
	Create KeyDeviceCreateCapabilities `json:"create"`
}

// KeyDeviceCreateCapabilities are the device creation capabilities of a Key.
type KeyDeviceCreateCapabilities struct {
	Reusable      bool     `json:"reusable"`
	Ephemeral     bool     `json:"ephemeral"`
	Preauthorized bool     `json:"preauthorized"`
	Tags          []string `json:"tags,omitempty"`
}

// Keys returns the list of keys for the current user.
func (c *Client) Keys(ctx context.Context) ([]string, error) {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/keys", c.baseURL(), c.tailnet)
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(b, resp)
	}

	var keys struct {
		Keys []*Key `json:"keys"`
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		return nil, err
	}
	ret := make([]string, 0, len(keys.Keys))
	for _, k := range keys.Keys {
		ret = append(ret, k.ID)
	}
	return ret, nil
}

// CreateKey creates a new key for the current user. Currently, only auth keys
// can be created. Returns the key itself, which cannot be retrieved again
// later, and the key metadata.
func (c *Client) CreateKey(ctx context.Context, caps KeyCapabilities) (string, *Key, error) {
	keyRequest := struct {
		Capabilities KeyCapabilities `json:"capabilities"`
	}{caps}
	bs, err := json.Marshal(keyRequest)
	if err != nil {
		return "", nil, err
	}

	path := fmt.Sprintf("%s/api/v2/tailnet/%s/keys", c.baseURL(), c.tailnet)
	req, err := http.NewRequestWithContext(ctx, "POST", path, bytes.NewReader(bs))
	if err != nil {
		return "", nil, err
	}

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, handleErrorResponse(b, resp)
	}

	var key struct {
		Key
		Secret string `json:"key"`
	}
	if err := json.Unmarshal(b, &key); err != nil {
		return "", nil, err
	}
	return key.Secret, &key.Key, nil
}

// Key returns the metadata for the given key ID. Currently, capabilities are
// only returned for auth keys, API keys only return general metadata.
func (c *Client) Key(ctx context.Context, id string) (*Key, error) {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/keys/%s", c.baseURL(), c.tailnet, id)
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(b, resp)
	}

	var key Key
	if err := json.Unmarshal(b, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// DeleteKey deletes the key with the given ID.
func (c *Client) DeleteKey(ctx context.Context, id string) error {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/keys/%s", c.baseURL(), c.tailnet, id)
	req, err := http.NewRequestWithContext(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return handleErrorResponse(b, resp)
	}
	return nil
}
