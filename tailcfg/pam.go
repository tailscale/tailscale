// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcfg

// PAMSessionCreateEntry describes a PAM session to be registered with the
// control plane. It is sent as part of a POST /machine/pam/sessions request.
type PAMSessionCreateEntry struct {
	// SessionKey is a connector-provided UUID that uniquely identifies the
	// session. It is used as the on-disk path component for replay retrieval.
	SessionKey string `json:"session_key"`

	// ServiceName is the VIP service name (e.g. "svc:my-db"). The control
	// plane resolves it to a stable VIP service ID.
	ServiceName string `json:"service_name,omitempty"`

	// SessionType is the recording type (e.g. "ssh", "database_query_log").
	SessionType string `json:"session_type,omitempty"`

	// ActorNodeID is the stable node ID of the actor (connecting user's device).
	// The control plane resolves it to a stable user ID.
	ActorNodeID string `json:"actor_node_id,omitempty"`

	// ClientIP is the source IP of the actor's connection.
	ClientIP string `json:"client_ip,omitempty"`

	// FirstEventTime is the session start time as Unix nanoseconds, UTC.
	FirstEventTime int64 `json:"first_event_time"`
}

// PAMSessionCreateResponse is the response body for POST /machine/pam/sessions.
type PAMSessionCreateResponse struct {
	// StableIDs contains the server-assigned stable PAM session IDs in the
	// same order as the request entries.
	StableIDs []string `json:"stable_ids"`
}

// PAMSessionUpdateEntry describes a LastEventTime update for a PAM session.
// It is sent as part of a PATCH /machine/pam/sessions request.
type PAMSessionUpdateEntry struct {
	// SessionKey identifies the session to update (connector-provided UUID).
	SessionKey string `json:"session_key"`

	// LastEventTime is the new last-event time as Unix nanoseconds, UTC.
	LastEventTime int64 `json:"last_event_time"`
}
