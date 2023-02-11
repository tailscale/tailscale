// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package version_test

import (
	"bytes"
	"os"
	"testing"

	ts "tailscale.com"
	"tailscale.com/version"
)

func TestAlpineTag(t *testing.T) {
	if tag := readAlpineTag(t, "../Dockerfile.base"); tag == "" {
		t.Fatal(`"FROM alpine:" not found in Dockerfile.base`)
	} else if tag != ts.AlpineDockerTag {
		t.Errorf("alpine version mismatch: Dockerfile.base has %q; ALPINE.txt has %q", tag, ts.AlpineDockerTag)
	}
	if tag := readAlpineTag(t, "../Dockerfile"); tag == "" {
		t.Fatal(`"FROM alpine:" not found in Dockerfile`)
	} else if tag != ts.AlpineDockerTag {
		t.Errorf("alpine version mismatch: Dockerfile has %q; ALPINE.txt has %q", tag, ts.AlpineDockerTag)
	}
}

func readAlpineTag(t *testing.T, file string) string {
	f, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(f, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		_, suf, ok := bytes.Cut(line, []byte("FROM alpine:"))
		if !ok {
			continue
		}
		return string(suf)
	}
	return ""
}

func TestShortAllocs(t *testing.T) {
	allocs := int(testing.AllocsPerRun(10000, func() {
		_ = version.Short()
	}))
	if allocs > 0 {
		t.Errorf("allocs = %v; want 0", allocs)
	}
}
