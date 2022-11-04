// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// No need to run this on Windows where CI's slow enough. Then we don't need to
// worry about "go.exe" etc.

//go:build !windows

package jsdeps

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDeps(t *testing.T) {
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "list", "-json", ".")
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Deps []string
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	for _, dep := range res.Deps {
		switch dep {
		case "runtime/pprof", "golang.org/x/net/http2/h2c", "net/http/pprof", "golang.org/x/net/proxy", "github.com/tailscale/goupnp":
			t.Errorf("package %q is not allowed as a dependency on JS", dep)
		}
	}
	t.Logf("got %d dependencies", len(res.Deps))
}
