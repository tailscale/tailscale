// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package api defines the login beacon API shared by the daemon and clients.
// It does not register or depend on daemon components.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"time"
)

// MaxBroadcastDuration bounds explicitly requested advertising attempts.
const MaxBroadcastDuration = 10 * time.Minute

// RequestRetention bounds session lifetimes and deletion tombstones.
const RequestRetention = 4 * time.Hour

// RequestLease expires silent senders, with room for the 60-second handling
// pause and several missed five-second broadcasts.
const RequestLease = 90 * time.Second

// MaxTrackedRequests bounds the receiver cache and client watch reconciliation.
const MaxTrackedRequests = 256

// Request is the client-facing projection of a MsgBeacon.
// RequestID and DeviceIDHash are hex-encoded.
type Request struct {
	RequestID    string `json:"requestID"`
	Hostname     string `json:"hostname"`
	DeviceKind   string `json:"deviceKind"`
	DeviceIDHash string `json:"deviceIDHash"`
	// RequesterID scopes the sender instance to its pinned LAN source. Clients
	// use it to replace superseded pending requests, never to authenticate peers.
	RequesterID string `json:"requesterID,omitempty"`
}

// Broadcast describes one explicitly requested LAN login attempt.
// Expires must be in the future and no more than ten minutes away. Repeating a
// PUT with the same ID and parameters does not restart or extend the attempt.
type Broadcast struct {
	Hostname string    `json:"hostname,omitempty"`
	Expires  time.Time `json:"expires"`
}

// Pending is metadata for a request known to the local receiver.
// It intentionally contains no authentication URL.
type Pending struct {
	Request
	Expires time.Time `json:"expires"`
}

// Status describes effective permission and local beacon activity.
type Status struct {
	Allowed          bool      `json:"allowed"`
	AcceptRequests   bool      `json:"acceptRequests"`
	Receiving        bool      `json:"receiving"`
	BroadcastID      string    `json:"broadcastID,omitempty"`
	BroadcastExpires time.Time `json:"broadcastExpires,omitzero"`
	Requests         []Pending `json:"requests"`
}

// Approval is the result of URL retrieval, not browser handoff or
// authentication. Callers must not log or persist this response.
type Approval struct {
	RequestID string `json:"requestID"`
	AuthURL   string `json:"authURL"`
}

// Approved carries the approver's self-reported hostname. It is
// untrusted (may be empty or "localhost"); UIs should sanitize for display.
type Approved struct {
	ApproverName string `json:"approverName"`
}

// NewID generates a fresh broadcast attempt ID.
func NewID() string {
	var id [16]byte
	rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

// ParseID validates a request or broadcast ID before using it in an API path.
func ParseID(raw string) ([16]byte, error) {
	var id [16]byte
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != len(id) {
		return id, errors.New("login beacon ID must be 32 hexadecimal characters")
	}
	copy(id[:], b)
	return id, nil
}

// DefaultURLAllowed accepts only the production authentication origin. Clients
// on a self-hosted control server must supply their own trusted origin policy.
func DefaultURLAllowed(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "login.tailscale.com" && u.User == nil && u.Opaque == ""
}
