// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !windows

package atomicfile

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoesNotOverwriteIrregularFiles(t *testing.T) {
	// Per tailscale/tailscale#7658 as one example, almost any imagined use of
	// atomicfile.Write should likely not attempt to overwrite an irregular file
	// such as a device node, socket, or named pipe.

	d := t.TempDir()
	special := filepath.Join(d, "special")

	// The least troublesome thing to make that is not a file is a unix socket.
	// Making a null device sadly requries root.
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: special, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	err = WriteFile(special, []byte("hello"), 0644)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "is not a regular file") {
		t.Fatalf("unexpected error: %v", err)
	}
}
