// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestBuildOpenresolv checks that the vendored openresolv sources still build
// into what the guest expects. It needs no VM, so an upstream bump that adds a
// build placeholder fails here in milliseconds. The alternative is a puzzling
// DNS failure several minutes into TestOpenresolvDNS.
func TestBuildOpenresolv(t *testing.T) {
	// buildOpenresolv itself fails on a surviving @NAME@ placeholder, so
	// reaching here already covers that.
	files, err := buildOpenresolv()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(openresolvInstall) {
		t.Fatalf("built %d files, want %d", len(files), len(openresolvInstall))
	}

	byPath := map[string]cloudInitFile{}
	for _, f := range files {
		byPath[f.path] = f
	}
	for _, want := range openresolvInstall {
		f, ok := byPath[want.guestPath]
		if !ok {
			t.Errorf("%s: not built", want.guestPath)
			continue
		}
		if len(f.content) == 0 {
			t.Errorf("%s: empty", want.guestPath)
		}
		if f.mode != want.mode {
			t.Errorf("%s: mode %q, want %q", want.guestPath, f.mode, want.mode)
		}
		if want.srcName != "" && !strings.HasPrefix(string(f.content), "#!/bin/sh") {
			t.Errorf("%s: does not start with a /bin/sh shebang", want.guestPath)
		}
	}

	// The substitutions have to have actually happened: resolvconf derives its
	// key directory from VARDIR, and net/dns's whole openresolv path hinges on
	// that directory being the one the test provisions.
	rc := string(byPath[openresolvSbinDir+"/resolvconf"].content)
	for _, want := range []string{
		"VARDIR=" + openresolvVarDir,
		"LIBEXECDIR=" + openresolvLibexecDir,
		`KEYDIR="$VARDIR/keys"`,
	} {
		if !strings.Contains(rc, want) {
			t.Errorf("built resolvconf does not contain %q", want)
		}
	}
}

// TestOpenresolvWriteFiles checks that the guest files survive a round trip
// through the cloud-init write_files section. resolvconf.in is 31 kB, so its
// base64 encoding is one very long YAML scalar, and a quoting or line-length
// mistake would show up as a guest that boots with a truncated shell script.
func TestOpenresolvWriteFiles(t *testing.T) {
	files, err := buildOpenresolv()
	if err != nil {
		t.Fatal(err)
	}
	var ud strings.Builder
	ud.WriteString("#cloud-config\n")
	writeCloudInitFiles(&ud, files)

	var got struct {
		WriteFiles []struct {
			Path        string `yaml:"path"`
			Encoding    string `yaml:"encoding"`
			Permissions string `yaml:"permissions"`
			Content     string `yaml:"content"`
		} `yaml:"write_files"`
	}
	if err := yaml.Unmarshal([]byte(ud.String()), &got); err != nil {
		t.Fatalf("user-data is not valid YAML: %v", err)
	}
	if len(got.WriteFiles) != len(files) {
		t.Fatalf("write_files has %d entries, want %d", len(got.WriteFiles), len(files))
	}
	for i, want := range files {
		g := got.WriteFiles[i]
		if g.Path != want.path {
			t.Errorf("entry %d: path %q, want %q", i, g.Path, want.path)
		}
		if g.Encoding != "b64" {
			t.Errorf("%s: encoding %q, want b64", want.path, g.Encoding)
		}
		if g.Permissions != want.mode {
			t.Errorf("%s: permissions %q, want %q", want.path, g.Permissions, want.mode)
		}
		content, err := base64.StdEncoding.DecodeString(g.Content)
		if err != nil {
			t.Errorf("%s: decoding content: %v", want.path, err)
			continue
		}
		if string(content) != string(want.content) {
			t.Errorf("%s: content survived the round trip as %d bytes, want %d",
				want.path, len(content), len(want.content))
		}
	}
}
