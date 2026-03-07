// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package local

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"tailscale.com/tailsync"
)

// SyncRootSet adds or updates a sync root.
func (lc *Client) SyncRootSet(ctx context.Context, root *tailsync.Root) error {
	_, err := lc.send(ctx, "PUT", "/localapi/v0/sync/roots", http.StatusCreated, jsonBody(root))
	return err
}

// SyncRootRemove removes a sync root by name.
func (lc *Client) SyncRootRemove(ctx context.Context, name string) error {
	_, err := lc.send(ctx, "DELETE", "/localapi/v0/sync/roots", http.StatusNoContent, strings.NewReader(name))
	return err
}

// SyncRootList returns all configured sync roots.
func (lc *Client) SyncRootList(ctx context.Context) ([]*tailsync.Root, error) {
	result, err := lc.get200(ctx, "/localapi/v0/sync/roots")
	if err != nil {
		return nil, err
	}
	var roots []*tailsync.Root
	err = json.Unmarshal(result, &roots)
	return roots, err
}

// SyncSessionSet adds or updates a sync session.
func (lc *Client) SyncSessionSet(ctx context.Context, session *tailsync.Session) error {
	_, err := lc.send(ctx, "PUT", "/localapi/v0/sync/sessions", http.StatusCreated, jsonBody(session))
	return err
}

// SyncSessionRemove stops and removes a sync session.
func (lc *Client) SyncSessionRemove(ctx context.Context, name string) error {
	_, err := lc.send(ctx, "DELETE", "/localapi/v0/sync/sessions", http.StatusNoContent, strings.NewReader(name))
	return err
}

// SyncSessionList returns all configured sync sessions.
func (lc *Client) SyncSessionList(ctx context.Context) ([]*tailsync.Session, error) {
	result, err := lc.get200(ctx, "/localapi/v0/sync/sessions")
	if err != nil {
		return nil, err
	}
	var sessions []*tailsync.Session
	err = json.Unmarshal(result, &sessions)
	return sessions, err
}

// SyncStatus returns status for all sync sessions.
func (lc *Client) SyncStatus(ctx context.Context) ([]*tailsync.SessionStatus, error) {
	result, err := lc.get200(ctx, "/localapi/v0/sync/status")
	if err != nil {
		return nil, err
	}
	var statuses []*tailsync.SessionStatus
	err = json.Unmarshal(result, &statuses)
	return statuses, err
}

// SyncSessionStatus returns status for a specific sync session.
func (lc *Client) SyncSessionStatus(ctx context.Context, name string) (*tailsync.SessionStatus, error) {
	result, err := lc.get200(ctx, "/localapi/v0/sync/status?name="+name)
	if err != nil {
		return nil, err
	}
	var status tailsync.SessionStatus
	err = json.Unmarshal(result, &status)
	return &status, err
}
