// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/types/key"
)

func TestNodeFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")

	nf := NodeFile{
		NodeKey:    key.NewNode(),
		MachineKey: key.NewMachine(),
		ServerInfo: ServerInfo{
			URL: "https://controlplane.tailscale.com",
			Key: key.NewMachine().Public(),
		},
	}

	if err := WriteNodeFile(path, nf); err != nil {
		t.Fatalf("WriteNodeFile: %v", err)
	}

	got, err := ReadNodeFile(path)
	if err != nil {
		t.Fatalf("ReadNodeFile: %v", err)
	}
	if !got.NodeKey.Equal(nf.NodeKey) {
		t.Errorf("node key mismatch")
	}
	if !got.MachineKey.Equal(nf.MachineKey) {
		t.Errorf("machine key mismatch")
	}
	if got.URL != nf.URL {
		t.Errorf("server URL = %q, want %q", got.URL, nf.URL)
	}
	if got.ServerInfo.Key != nf.ServerInfo.Key {
		t.Errorf("server key mismatch")
	}
}

// TestNodeFileFormat verifies that ReadNodeFile can parse a fixed JSON literal,
// ensuring we don't accidentally change the on-disk format.
func TestNodeFileFormat(t *testing.T) {
	const fileContents = `{
  "node_key": "privkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "machine_key": "privkey:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
  "server_url": "https://controlplane.tailscale.com",
  "server_key": "mkey:1111111111111111111111111111111111111111111111111111111111111111"
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")
	if err := os.WriteFile(path, []byte(fileContents), 0600); err != nil {
		t.Fatal(err)
	}

	nf, err := ReadNodeFile(path)
	if err != nil {
		t.Fatalf("ReadNodeFile: %v", err)
	}
	if nf.NodeKey.IsZero() {
		t.Error("node key is zero")
	}
	if nf.MachineKey.IsZero() {
		t.Error("machine key is zero")
	}
	if nf.URL != "https://controlplane.tailscale.com" {
		t.Errorf("server URL = %q", nf.URL)
	}
	if nf.ServerInfo.Key.IsZero() {
		t.Error("server key is zero")
	}
}

// TestNodeFileWriteFormat verifies that WriteNodeFile produces the expected
// JSON field names.
func TestNodeFileWriteFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")

	nf := NodeFile{
		NodeKey:    key.NewNode(),
		MachineKey: key.NewMachine(),
		ServerInfo: ServerInfo{
			URL: "https://example.com",
			Key: key.NewMachine().Public(),
		},
	}

	if err := WriteNodeFile(path, nf); err != nil {
		t.Fatalf("WriteNodeFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parsing written JSON: %v", err)
	}
	for _, field := range []string{"node_key", "machine_key", "server_url", "server_key"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing JSON field %q in written file", field)
		}
	}
}
