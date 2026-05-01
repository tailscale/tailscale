// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsp

import (
	"encoding/json"
	"fmt"
	"os"

	"tailscale.com/types/key"
)

// ServerInfo identifies a coordination server by its URL and Noise public key.
type ServerInfo struct {
	// URL is the base URL of the coordination server, without any path
	// (e.g. "https://controlplane.tailscale.com").
	//
	// There is no default value; a URL must always be supplied.
	URL string `json:"server_url"`

	// Key is the server's Noise public key, used to establish an encrypted
	// channel between the client and the coordination server.
	Key key.MachinePublic `json:"server_key"`
}

// NodeFile is the JSON structure for a node credentials file. It contains
// the private keys that authenticate a node to a coordination server.
//
// Example:
//
//	{
//	  "node_key": "privkey:...",
//	  "machine_key": "privkey:...",
//	  "server_url": "https://controlplane.tailscale.com",
//	  "server_key": "mkey:..."
//	}
//
// Note that node and machine private keys share the same "privkey:"
// textual form; they are disambiguated by the surrounding JSON field
// names rather than by any prefix in the key itself.
type NodeFile struct {
	// NodeKey is the node's WireGuard private key. The corresponding
	// public key identifies this node to other peers.
	NodeKey key.NodePrivate `json:"node_key"`

	// MachineKey is the machine's private key. It authenticates this
	// machine to the coordination server over Noise.
	MachineKey key.MachinePrivate `json:"machine_key"`

	ServerInfo // server_url and server_key
}

// ReadNodeFile reads and parses a node JSON file.
func ReadNodeFile(path string) (NodeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return NodeFile{}, err
	}
	var nf NodeFile
	if err := json.Unmarshal(data, &nf); err != nil {
		return NodeFile{}, fmt.Errorf("parsing node file %q: %w", path, err)
	}
	return nf, nil
}

// WriteNodeFile writes a node JSON file. The file is created with mode 0600.
func WriteNodeFile(path string, nf NodeFile) error {
	if err := nf.Check(); err != nil {
		return fmt.Errorf("invalid NodeFile: %w", err)
	}
	return os.WriteFile(path, nf.AsJSON(), 0600)
}

// AsJSON returns nf as a pretty-printed JSON object, terminated by a newline.
//
// It always succeeds and always returns a valid JSON object. It does not
// validate that the fields of nf are non-zero; it is the caller's
// responsibility to call [NodeFile.Check] first if they want to reject
// incomplete NodeFiles.
func (nf NodeFile) AsJSON() []byte {
	out, err := json.MarshalIndent(nf, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("NodeFile.AsJSON: %v", err)) // unreachable: all fields marshal successfully
	}
	return append(out, '\n')
}

// Check reports whether nf has all required fields set.
// It returns an error describing the first zero-valued field, if any.
func (nf NodeFile) Check() error {
	if nf.NodeKey.IsZero() {
		return fmt.Errorf("node_key is missing")
	}
	if nf.MachineKey.IsZero() {
		return fmt.Errorf("machine_key is missing")
	}
	if nf.URL == "" {
		return fmt.Errorf("server_url is missing")
	}
	if nf.ServerInfo.Key.IsZero() {
		return fmt.Errorf("server_key is missing")
	}
	return nil
}
