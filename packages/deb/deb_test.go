// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package deb

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/goreleaser/nfpm"
	_ "github.com/goreleaser/nfpm/deb"
)

func TestDebInfo(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    *Info
		wantErr bool
	}{
		{
			name: "simple",
			in:   mkTestDeb("1.2.3", "amd64"),
			want: &Info{
				Version: "1.2.3",
				Arch:    "amd64",
				Control: mkControl(
					"Package", "tailscale",
					"Version", "1.2.3",
					"Section", "net",
					"Priority", "extra",
					"Architecture", "amd64",
					"Installed-Size", "0",
					"Description", "test package"),
			},
		},
		{
			name: "arm64",
			in:   mkTestDeb("1.2.3", "arm64"),
			want: &Info{
				Version: "1.2.3",
				Arch:    "arm64",
				Control: mkControl(
					"Package", "tailscale",
					"Version", "1.2.3",
					"Section", "net",
					"Priority", "extra",
					"Architecture", "arm64",
					"Installed-Size", "0",
					"Description", "test package"),
			},
		},
		{
			name: "unstable",
			in:   mkTestDeb("1.7.25", "amd64"),
			want: &Info{
				Version: "1.7.25",
				Arch:    "amd64",
				Control: mkControl(
					"Package", "tailscale",
					"Version", "1.7.25",
					"Section", "net",
					"Priority", "extra",
					"Architecture", "amd64",
					"Installed-Size", "0",
					"Description", "test package"),
			},
		},

		// These truncation tests assume the structure of a .deb
		// package, which is as follows:
		//  magic: 8 bytes
		//  file header: 60 bytes, before each file blob
		//
		// The first file in a .deb ar is "debian-binary", which is 4
		// bytes long and consists of "2.0\n".
		// The second file is control.tar.gz, which is what we care
		// about introspecting for metadata.
		// The final file is data.tar.gz, which we don't care about.
		//
		// The first file in control.tar.gz is the "control" file we
		// want to read for metadata.
		{
			name:    "truncated_ar_magic",
			in:      mkTestDeb("1.7.25", "amd64")[:4],
			wantErr: true,
		},
		{
			name:    "truncated_ar_header",
			in:      mkTestDeb("1.7.25", "amd64")[:30],
			wantErr: true,
		},
		{
			name: "missing_control_tgz",
			// Truncate right after the "debian-binary" file, which
			// makes the file a valid 1-file archive that's missing
			// control.tar.gz.
			in:      mkTestDeb("1.7.25", "amd64")[:72],
			wantErr: true,
		},
		{
			name:    "truncated_tgz",
			in:      mkTestDeb("1.7.25", "amd64")[:172],
			wantErr: true,
		},
	}

	for _, test := range tests {
		// mkTestDeb returns non-deterministic output due to
		// timestamps embedded in the package file, so compute the
		// wanted hashes on the fly here.
		if test.want != nil {
			test.want.MD5 = mkHash(test.in, md5.New)
			test.want.SHA1 = mkHash(test.in, sha1.New)
			test.want.SHA256 = mkHash(test.in, sha256.New)
		}

		t.Run(test.name, func(t *testing.T) {
			b := bytes.NewBuffer(test.in)
			got, err := Read(b)
			if err != nil {
				if test.wantErr {
					t.Logf("got expected error: %v", err)
					return
				}
				t.Fatalf("reading deb info: %v", err)
			}
			if diff := diff(got, test.want); diff != "" {
				t.Fatalf("parsed info diff (-got+want):\n%s", diff)
			}
		})
	}
}

func diff(got, want any) string {
	matchField := func(name string) func(p cmp.Path) bool {
		return func(p cmp.Path) bool {
			if len(p) != 3 {
				return false
			}
			return p[2].String() == "."+name
		}
	}
	toLines := cmp.Transformer("lines", func(b []byte) []string { return strings.Split(string(b), "\n") })
	toHex := cmp.Transformer("hex", func(b []byte) string { return hex.EncodeToString(b) })
	return cmp.Diff(got, want,
		cmp.FilterPath(matchField("Control"), toLines),
		cmp.FilterPath(matchField("MD5"), toHex),
		cmp.FilterPath(matchField("SHA1"), toHex),
		cmp.FilterPath(matchField("SHA256"), toHex))
}

func mkTestDeb(version, arch string) []byte {
	info := nfpm.WithDefaults(&nfpm.Info{
		Name:        "tailscale",
		Description: "test package",
		Arch:        arch,
		Platform:    "linux",
		Version:     version,
		Section:     "net",
		Priority:    "extra",
	})

	pkg, err := nfpm.Get("deb")
	if err != nil {
		panic(fmt.Sprintf("getting deb packager: %v", err))
	}

	var b bytes.Buffer
	if err := pkg.Package(info, &b); err != nil {
		panic(fmt.Sprintf("creating deb package: %v", err))
	}

	return b.Bytes()
}

func mkControl(fs ...string) []byte {
	if len(fs)%2 != 0 {
		panic("odd number of control file fields")
	}
	var b bytes.Buffer
	for i := 0; i < len(fs); i = i + 2 {
		k, v := fs[i], fs[i+1]
		fmt.Fprintf(&b, "%s: %s\n", k, v)
	}
	return bytes.TrimSpace(b.Bytes())
}

func mkHash(b []byte, hasher func() hash.Hash) []byte {
	h := hasher()
	h.Write(b)
	return h.Sum(nil)
}
