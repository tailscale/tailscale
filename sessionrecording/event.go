// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sessionrecording

import (
	"encoding/json"
	"time"

	"k8s.io/apiserver/pkg/endpoints/request"
	"tailscale.com/tailcfg"
)

const (
	KubernetesAPIEventType = "Kubernetes API Request"
)

// Event represents the top-level structure of a tsrecorder event.
type Event struct {
	Type       string              `json:"type"`
	ID         string              `json:"id"`
	Timestamp  time.Time           `json:"timestamp"`
	UserAgent  string              `json:"userAgent"`
	Request    Request             `json:"request"`
	Kubernetes request.RequestInfo `json:"kubernetes"`
	Source     Source              `json:"source"`
	LocalUser  string              `json:"localUser"`
}

type Source struct {
	// Node is the FQDN of the node originating the connection.
	// It is also the MagicDNS name for the node.
	// It does not have a trailing dot.
	// e.g. "host.tail-scale.ts.net"
	Node string `json:"node"`

	// NodeID is the node ID of the node originating the connection.
	NodeID tailcfg.StableNodeID `json:"nodeID"`

	// Tailscale-specific fields:
	// NodeTags is the list of tags on the node originating the connection (if any).
	NodeTags []string `json:"nodeTags,omitempty"`

	// NodeUserID is the user ID of the node originating the connection (if not tagged).
	NodeUserID tailcfg.UserID `json:"nodeUserID,omitempty"` // if not tagged

	// NodeUser is the LoginName of the node originating the connection (if not tagged).
	NodeUser string `json:"nodeUser,omitempty"`
}

// Request holds information about a request.
type Request struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"` // Using json.RawMessage to handle arbitrary JSON content
}

// Kubernetes contains Kubernetes-specific event details.
type KubernetesEvent struct {
	IsResourceRequest bool   `json:"isResourceRequest"`
	Verb              string `json:"verb"`
	APIGroup          string `json:"apiGroup"`
	APIVersion        string `json:"apiVersion"`
	Resource          string `json:"resource"`
	Subresource       string `json:"subresource"`
	Namespace         string `json:"namespace"`
	Name              string `json:"name"`
}

// User represents the user who initiated the event.
type User struct {
	Email string `json:"email"`
}
