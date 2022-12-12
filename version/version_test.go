// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version_test

import (
	"bytes"
	"os"
	"testing"

	ts "tailscale.com"
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
