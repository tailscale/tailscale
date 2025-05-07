// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestJoinDir(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		in     string
		want   string // just relative to m.Dir
		wantOk bool
	}{
		{"", "", false},
		{"foo", "foo", true},
		{"./foo", "", false},
		{"../foo", "", false},
		{"foo/bar", "", false},
		{"😋", "😋", true},
		{"\xde\xad\xbe\xef", "", false},
		{"foo.partial", "", false},
		{"foo.deleted", "", false},
		{strings.Repeat("a", 1024), "", false},
		{"foo:bar", "", false},
	}
	for _, tt := range tests {
		got, gotErr := joinDir(dir, tt.in)
		got, _ = filepath.Rel(dir, got)
		gotOk := gotErr == nil
		if got != tt.want || gotOk != tt.wantOk {
			t.Errorf("joinDir(%q) = (%v, %v), want (%v, %v)", tt.in, got, gotOk, tt.want, tt.wantOk)
		}
	}
}

func TestNextFilename(t *testing.T) {
	tests := []struct {
		in    string
		want  string
		want2 string
	}{
		{"foo", "foo (1)", "foo (2)"},
		{"foo(1)", "foo(1) (1)", "foo(1) (2)"},
		{"foo.tar", "foo (1).tar", "foo (2).tar"},
		{"foo.tar.gz", "foo (1).tar.gz", "foo (2).tar.gz"},
		{".bashrc", ".bashrc (1)", ".bashrc (2)"},
		{"fizz buzz.torrent", "fizz buzz (1).torrent", "fizz buzz (2).torrent"},
		{"rawr 2023.12.15.txt", "rawr 2023.12.15 (1).txt", "rawr 2023.12.15 (2).txt"},
		{"IMG_7934.JPEG", "IMG_7934 (1).JPEG", "IMG_7934 (2).JPEG"},
		{"my song.mp3", "my song (1).mp3", "my song (2).mp3"},
		{"archive.7z", "archive (1).7z", "archive (2).7z"},
		{"foo/bar/fizz", "foo/bar/fizz (1)", "foo/bar/fizz (2)"},
		{"新完全マスター　N2　文法.pdf", "新完全マスター　N2　文法 (1).pdf", "新完全マスター　N2　文法 (2).pdf"},
	}

	for _, tt := range tests {
		if got := nextFilename(tt.in); got != tt.want {
			t.Errorf("NextFilename(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if got2 := nextFilename(tt.want); got2 != tt.want2 {
			t.Errorf("NextFilename(%q) = %q, want %q", tt.want, got2, tt.want2)
		}
	}
}
