// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"tailscale.com/tailcfg"
	"tailscale.com/util/httpm"
)

// pamSessionCreateRequest is the wire body for POST /machine/pam/sessions.
type pamSessionCreateRequest struct {
	NodeKey  string                          `json:"node_key"`
	Sessions []tailcfg.PAMSessionCreateEntry `json:"sessions"`
}

// pamSessionUpdateRequest is the wire body for PATCH /machine/pam/sessions.
type pamSessionUpdateRequest struct {
	NodeKey  string                          `json:"node_key"`
	Sessions []tailcfg.PAMSessionUpdateEntry `json:"sessions"`
}

// CreatePAMSessions registers one or more PAM session recordings with the
// control plane. It returns the server-assigned stable session IDs in the same
// order as sessions.
//
// The server must be running (Up must have been called).
func (s *Server) CreatePAMSessions(ctx context.Context, sessions []tailcfg.PAMSessionCreateEntry) ([]string, error) {
	if err := s.Start(); err != nil {
		return nil, err
	}
	nodeKey := s.lb.NodeKey()
	if nodeKey.IsZero() {
		return nil, fmt.Errorf("tsnet: CreatePAMSessions: node key not yet available")
	}

	body, err := json.Marshal(pamSessionCreateRequest{
		NodeKey:  nodeKey.String(),
		Sessions: sessions,
	})
	if err != nil {
		return nil, fmt.Errorf("tsnet: CreatePAMSessions: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, httpm.POST, "https://unused/machine/pam/sessions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("tsnet: CreatePAMSessions: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.lb.DoNoiseRequest(req)
	if err != nil {
		return nil, fmt.Errorf("tsnet: CreatePAMSessions: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsnet: CreatePAMSessions: control plane returned %s", resp.Status)
	}

	var result tailcfg.PAMSessionCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("tsnet: CreatePAMSessions: decode response: %w", err)
	}
	return result.StableIDs, nil
}

// UpdatePAMSessions updates the LastEventTime for one or more PAM sessions on
// the control plane. Errors from the control plane are returned but callers
// should treat them as non-fatal (the session may not exist yet due to a race
// with session creation).
//
// The server must be running (Up must have been called).
func (s *Server) UpdatePAMSessions(ctx context.Context, sessions []tailcfg.PAMSessionUpdateEntry) error {
	if err := s.Start(); err != nil {
		return err
	}
	nodeKey := s.lb.NodeKey()
	if nodeKey.IsZero() {
		return fmt.Errorf("tsnet: UpdatePAMSessions: node key not yet available")
	}

	body, err := json.Marshal(pamSessionUpdateRequest{
		NodeKey:  nodeKey.String(),
		Sessions: sessions,
	})
	if err != nil {
		return fmt.Errorf("tsnet: UpdatePAMSessions: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, httpm.PATCH, "https://unused/machine/pam/sessions", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("tsnet: UpdatePAMSessions: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.lb.DoNoiseRequest(req)
	if err != nil {
		return fmt.Errorf("tsnet: UpdatePAMSessions: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("tsnet: UpdatePAMSessions: control plane returned %s", resp.Status)
	}
	return nil
}
