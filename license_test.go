// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscaleroot

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/util/set"
)

func normalizeLineEndings(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

// TestLicenseHeaders checks that all Go files in the tree
// directory tree have a correct-looking Tailscale license header.
func TestLicenseHeaders(t *testing.T) {
	want := normalizeLineEndings([]byte(strings.TrimLeft(`
// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
`, "\n")))

	exceptions := set.Of(
		// Subprocess test harness code
		"util/winutil/testdata/testrestartableprocesses/main.go",
		"util/winutil/subprocess_windows_test.go",

		// WireGuard copyright
		"cmd/tailscale/cli/authenticode_windows.go",
		"wgengine/router/osrouter/ifconfig_windows.go",

		// noiseexplorer.com copyright
		"control/controlbase/noiseexplorer_test.go",

		// Generated eBPF management code
		"derp/xdp/bpf_bpfeb.go",
		"derp/xdp/bpf_bpfel.go",

		// Generated kube deepcopy funcs file starts with a Go build tag + an empty line
		"k8s-operator/apis/v1alpha1/zz_generated.deepcopy.go",
	)

	err := filepath.Walk(".", func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("path %s: %v", path, err)
		}
		if exceptions.Contains(filepath.ToSlash(path)) {
			return nil
		}
		base := filepath.Base(path)
		switch base {
		case ".git", "node_modules", "tempfork":
			return filepath.SkipDir
		}
		switch base {
		case "zsyscall_windows.go":
			// Generated code.
			return nil
		}

		if strings.HasSuffix(base, ".config.ts") {
			return nil
		}
		if strings.HasSuffix(base, "_string.go") {
			// Generated file from go:generate stringer
			return nil
		}

		ext := filepath.Ext(base)
		switch ext {
		default:
			return nil
		case ".go", ".ts", ".tsx":
		}

		buf := make([]byte, 512)
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if n, err := io.ReadAtLeast(f, buf, 512); err != nil && err != io.ErrUnexpectedEOF {
			return err
		} else {
			buf = buf[:n]
		}

		buf = normalizeLineEndings(buf)

		bufNoTrunc := buf
		if i := bytes.Index(buf, []byte("\npackage ")); i != -1 {
			buf = buf[:i]
		}

		if bytes.Contains(buf, want) {
			return nil
		}

		if bytes.Contains(bufNoTrunc, []byte("BSD-3-Clause\npackage ")) {
			t.Errorf("file %s has license header as a package doc; add a blank line before the package line", path)
			return nil
		}

		t.Errorf("file %s is missing Tailscale copyright header:\n\n%s", path, want)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
}
