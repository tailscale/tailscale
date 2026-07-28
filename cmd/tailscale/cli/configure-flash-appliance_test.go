// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_flashappliance

package cli

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestCheckPartitionFits(t *testing.T) {
	files := buildZip(t, map[string][]byte{
		"boot.img": bytes.Repeat([]byte{0xAB}, 1<<20),
		"root.img": bytes.Repeat([]byte{0xCD}, 4<<20),
	})

	if err := checkPartitionFits(files, "boot.img", 2<<20); err != nil {
		t.Errorf("boot.img within limit: %v", err)
	}
	if err := checkPartitionFits(files, "root.img", 1<<20); err == nil {
		t.Errorf("root.img over limit: expected error")
	}
	if err := checkPartitionFits(files, "missing.img", 1<<20); err == nil {
		t.Errorf("missing file: expected error")
	}
}

// buildZip returns the *zip.File entries for an in-memory zip containing
// the given members.
func buildZip(t *testing.T, members map[string][]byte) []*zip.File {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip.Create %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip.Write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	return zr.File
}
