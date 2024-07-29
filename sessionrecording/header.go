// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sessionrecording

import "tailscale.com/tailcfg"

// CastHeader is the header of an asciinema file.
type CastHeader struct {
	// Version is the asciinema file format version.
	Version int `json:"version"`

	// Width is the terminal width in characters.
	// It is non-zero for Pty sessions.
	Width int `json:"width"`

	// Height is the terminal height in characters.
	// It is non-zero for Pty sessions.
	Height int `json:"height"`

	// Timestamp is the unix timestamp of when the recording started.
	Timestamp int64 `json:"timestamp"`

	// Command is the command that was executed.
	// Typically empty for shell sessions.
	Command string `json:"command,omitempty"`

	// SrcNode is the FQDN of the node originating the connection.
	// It is also the MagicDNS name for the node.
	// It does not have a trailing dot.
	// e.g. "host.tail-scale.ts.net"
	SrcNode string `json:"srcNode"`

	// SrcNodeID is the node ID of the node originating the connection.
	SrcNodeID tailcfg.StableNodeID `json:"srcNodeID"`

	// Tailscale-specific fields:
	// SrcNodeTags is the list of tags on the node originating the connection (if any).
	SrcNodeTags []string `json:"srcNodeTags,omitempty"`

	// SrcNodeUserID is the user ID of the node originating the connection (if not tagged).
	SrcNodeUserID tailcfg.UserID `json:"srcNodeUserID,omitempty"` // if not tagged

	// SrcNodeUser is the LoginName of the node originating the connection (if not tagged).
	SrcNodeUser string `json:"srcNodeUser,omitempty"`

	// Fields that are only set for Tailscale SSH session recordings:

	// Env is the environment variables of the session.
	// Only "TERM" is set (2023-03-22).
	Env map[string]string `json:"env"`

	// SSHUser is the username as presented by the client.
	SSHUser string `json:"sshUser"` // as presented by the client

	// LocalUser is the effective username on the server.
	LocalUser string `json:"localUser"`

	// ConnectionID uniquely identifies a connection made to the SSH server.
	// It may be shared across multiple sessions over the same connection in
	// case of SSH multiplexing.
	ConnectionID string `json:"connectionID"`

	// Fields that are only set for Kubernetes API server proxy session recordings:

	Kubernetes *Kubernetes `json:"kubernetes,omitempty"`
}

// Kubernetes contains 'kubectl exec' session specific information for
// tsrecorder.
type Kubernetes struct {
	// PodName is the name of the Pod being exec-ed.
	PodName string
	// Namespace is the namespace in which is the Pod that is being exec-ed.
	Namespace string
	// Container is the container being exec-ed.
	Container string
}
