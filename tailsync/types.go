// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tailsync provides bidirectional real-time file synchronization
// between Tailscale nodes. The actual implementation lives in package
// tailsyncimpl. These packages are separated to allow users to refer to
// the interfaces without depending on the implementation.
package tailsync

import (
	"os"
	"time"
)

// Root is a directory exported for sync on this node.
type Root struct {
	// Name is how this root appears to remote nodes.
	Name string `json:"name,omitempty"`

	// Path is the absolute path to the directory on this machine.
	Path string `json:"path,omitempty"`

	// As is the UNIX or Windows username used to access files in this root.
	// File read/write permissions are enforced based on this username.
	As string `json:"as,omitempty"`

	// Ignore is a list of additional glob patterns to exclude from sync.
	Ignore []string `json:"ignore,omitempty"`
}

// Mode defines the directionality of a sync session.
type Mode string

const (
	// ModeTwoWaySafe is the default mode: bidirectional sync with conflict copies.
	ModeTwoWaySafe Mode = "two-way-safe"
	// ModePush syncs only from local to remote.
	ModePush Mode = "push"
	// ModePull syncs only from remote to local.
	ModePull Mode = "pull"
)

// Session defines a sync relationship between a local root and a remote root.
type Session struct {
	// Name identifies this session.
	Name string `json:"name,omitempty"`

	// LocalRoot is the name of a local Root.
	LocalRoot string `json:"localRoot,omitempty"`

	// PeerID is the stable node ID of the remote peer.
	PeerID string `json:"peerID,omitempty"`

	// RemoteRoot is the name of the root on the remote peer.
	RemoteRoot string `json:"remoteRoot,omitempty"`

	// Mode controls the sync direction.
	Mode Mode `json:"mode,omitempty"`
}

// SessionState represents the current state of a sync session.
type SessionState string

const (
	SessionStateIdle         SessionState = "idle"
	SessionStateSyncing      SessionState = "syncing"
	SessionStateReconciling  SessionState = "reconciling"
	SessionStateError        SessionState = "error"
	SessionStateDisconnected SessionState = "disconnected"
)

// SessionStatus reports the current status of a sync session.
type SessionStatus struct {
	Name         string         `json:"name"`
	State        SessionState   `json:"state"`
	FilesInSync  int64          `json:"filesInSync"`
	FilesPending int64          `json:"filesPending"`
	BytesSent    int64          `json:"bytesSent"`
	BytesRecv    int64          `json:"bytesRecv"`
	Conflicts    []ConflictInfo `json:"conflicts,omitempty"`
	LastSyncAt   time.Time      `json:"lastSyncAt,omitempty"`
	Error        string         `json:"error,omitempty"`
}

// ConflictInfo describes a sync conflict for a single file.
type ConflictInfo struct {
	Path         string    `json:"path"`
	ConflictPath string    `json:"conflictPath"`
	DetectedAt   time.Time `json:"detectedAt"`
}

// FileEntry represents a single file's state in the sync index.
type FileEntry struct {
	// Path is the relative path within the root.
	Path string `json:"path"`

	// Size is the file size in bytes.
	Size int64 `json:"size"`

	// ModTime is the file's modification time.
	ModTime time.Time `json:"modTime"`

	// Mode is the file's permission bits.
	Mode os.FileMode `json:"mode"`

	// Hash is the SHA-256 content hash.
	Hash [32]byte `json:"hash"`

	// Deleted marks the file as a tombstone.
	Deleted bool `json:"deleted,omitempty"`

	// Sequence is a monotonically increasing version per change.
	Sequence uint64 `json:"seq"`

	// IsSymlink indicates the entry is a symlink.
	IsSymlink bool `json:"isSymlink,omitempty"`

	// SymlinkTarget is the symlink target path (relative only).
	SymlinkTarget string `json:"symlinkTarget,omitempty"`
}
