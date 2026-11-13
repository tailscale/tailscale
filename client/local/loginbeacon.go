// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package local

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"tailscale.com/feature/loginbeacon/api"
)

// LoginBeaconStatus returns local beacon permission, activity and pending requests.
func (lc *Client) LoginBeaconStatus(ctx context.Context) (*api.Status, error) {
	data, err := lc.send(ctx, http.MethodGet, "/localapi/v0/loginbeacon/", http.StatusOK, nil)
	if err != nil {
		return nil, err
	}
	status, err := decodeJSON[api.Status](data)
	return &status, err
}

// LoginBeaconRequests lists pending metadata, without retrieving login URLs.
func (lc *Client) LoginBeaconRequests(ctx context.Context) ([]api.Pending, error) {
	data, err := lc.send(ctx, http.MethodGet, "/localapi/v0/loginbeacon/requests", http.StatusOK, nil)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]api.Pending](data)
}

// StartLoginBeacon starts a bounded attempt. Repeating its ID and configuration
// is idempotent; callers must generate a fresh ID for a new attempt.
func (lc *Client) StartLoginBeacon(ctx context.Context, id string, config api.Broadcast) error {
	if _, err := api.ParseID(id); err != nil {
		return err
	}
	_, err := lc.send(ctx, http.MethodPut, "/localapi/v0/loginbeacon/broadcasts/"+id, http.StatusNoContent, jsonBody(config))
	return err
}

// StopLoginBeacon stops only the specified attempt, including after replacement.
func (lc *Client) StopLoginBeacon(ctx context.Context, id string) error {
	if _, err := api.ParseID(id); err != nil {
		return err
	}
	_, err := lc.send(ctx, http.MethodDelete, "/localapi/v0/loginbeacon/broadcasts/"+id, http.StatusNoContent, nil)
	return err
}

// ApproveLoginBeacon retrieves an authentication URL without opening or deleting
// it. Delete the request after successful browser handoff. Do not log the result.
func (lc *Client) ApproveLoginBeacon(ctx context.Context, id string) (*api.Approval, error) {
	if _, err := api.ParseID(id); err != nil {
		return nil, err
	}
	data, err := lc.send(ctx, http.MethodPost, "/localapi/v0/loginbeacon/requests/"+id+"/approval", http.StatusOK, nil)
	if err != nil {
		return nil, err
	}
	result, err := decodeJSON[api.Approval](data)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(result.RequestID, id) {
		return nil, errors.New("login beacon approval request ID mismatch")
	}
	return &result, nil
}

// DeleteLoginBeacon suppresses a request until its expiry.
func (lc *Client) DeleteLoginBeacon(ctx context.Context, id string) error {
	if _, err := api.ParseID(id); err != nil {
		return err
	}
	_, err := lc.send(ctx, http.MethodDelete, "/localapi/v0/loginbeacon/requests/"+id, http.StatusNoContent, nil)
	return err
}
