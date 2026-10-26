// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestIsDangerousEnvVar(t *testing.T) {
	tests := []struct {
		name      string
		dangerous bool
	}{
		{"LD_PRELOAD", true},
		{"LD_LIBRARY_PATH", true},
		{"LD_AUDIT", true},
		{"LD_DEBUG", true},
		{"LD_PROFILE", true},
		{"ld_preload", true},
		{"DYLD_INSERT_LIBRARIES", true},
		{"DYLD_LIBRARY_PATH", true},
		{"DYLD_FRAMEWORK_PATH", true},
		{"dyld_insert_libraries", true},
		{"GOTRACEBACK", true},
		{"GCONV_PATH", true},
		{"gconv_path", true},
		{"LOCPATH", true},
		{"locpath", true},
		{"NLSPATH", true},
		{"nlspath", true},
		{"HOSTALIASES", true},
		{"hostaliases", true},
		{"RES_OPTIONS", true},
		{"res_options", true},
		{"GLIBC_TUNABLES", true},
		{"glibc_tunables", true},
		{"TERM", false},
		{"LANG", false},
		{"LC_ALL", false},
		{"PATH", false},
		{"HOME", false},
		{"LDFLAGS", false},
		{"MY_LD_PRELOAD", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDangerousEnvVar(tt.name); got != tt.dangerous {
				t.Errorf("isDangerousEnvVar(%q) = %v, want %v", tt.name, got, tt.dangerous)
			}
		})
	}
}

func TestMatchAcceptEnvPattern(t *testing.T) {
	testCases := []struct {
		pattern string
		target  string
		match   bool
	}{
		{pattern: "*", target: "EXAMPLE_ENV", match: true},
		{pattern: "***", target: "123456", match: true},

		{pattern: "?", target: "A", match: true},
		{pattern: "?", target: "123", match: false},

		{pattern: "?*", target: "EXAMPLE_2", match: true},
		{pattern: "?*", target: "", match: false},

		{pattern: "*?", target: "A", match: true},
		{pattern: "*?", target: "", match: false},

		{pattern: "??", target: "CC", match: true},
		{pattern: "??", target: "123", match: false},

		{pattern: "*?*", target: "ABCDEFG", match: true},
		{pattern: "*?*", target: "C", match: true},
		{pattern: "*?*", target: "", match: false},

		{pattern: "?*?", target: "ABCDEFG", match: true},
		{pattern: "?*?", target: "A", match: false},

		{pattern: "**?TEST", target: "_TEST", match: true},
		{pattern: "**?TEST", target: "_TESTING", match: false},

		{pattern: "TEST**?", target: "TEST_", match: true},
		{pattern: "TEST**?", target: "A_TEST_", match: false},

		{pattern: "TEST_*", target: "TEST_A", match: true},
		{pattern: "TEST_*", target: "TEST_A_LONG_ENVIRONMENT_VARIABLE_NAME", match: true},
		{pattern: "TEST_*", target: "TEST", match: false},

		{pattern: "EXAMPLE_?_ENV", target: "EXAMPLE_A_ENV", match: true},
		{pattern: "EXAMPLE_?_ENV", target: "EXAMPLE_ENV", match: false},

		{pattern: "EXAMPLE_*_ENV", target: "EXAMPLE_aBcd2231---_ENV", match: true},
		{pattern: "EXAMPLE_*_ENV", target: "EXAMPLEENV", match: false},

		{pattern: "COMPLICA?ED_PATTERN*", target: "COMPLICATED_PATTERN_REST", match: true},
		{pattern: "COMPLICA?ED_PATTERN*", target: "COMPLICATED_PATT", match: false},

		{pattern: "COMPLICAT???ED_PATT??ERN", target: "COMPLICAT123ED_PATTggERN", match: true},
		{pattern: "COMPLICAT???ED_PATT??ERN", target: "COMPLICATED_PATTERN", match: false},

		{pattern: "DIRECT_MATCH", target: "DIRECT_MATCH", match: true},
		{pattern: "DIRECT_MATCH", target: "MISS", match: false},

		// OpenSSH compatibility cases
		// See https://github.com/openssh/openssh-portable/blob/master/regress/unittests/match/tests.c
		{pattern: "", target: "", match: true},
		{pattern: "aaa", target: "", match: false},
		{pattern: "", target: "aaa", match: false},
		{pattern: "aaaa", target: "aaa", match: false},
		{pattern: "aaa", target: "aaaa", match: false},
		{pattern: "*", target: "", match: true},
		{pattern: "?", target: "a", match: true},
		{pattern: "a?", target: "aa", match: true},
		{pattern: "*", target: "a", match: true},
		{pattern: "a*", target: "aa", match: true},
		{pattern: "?*", target: "aa", match: true},
		{pattern: "**", target: "aa", match: true},
		{pattern: "?a", target: "aa", match: true},
		{pattern: "*a", target: "aa", match: true},
		{pattern: "a?", target: "ba", match: false},
		{pattern: "a*", target: "ba", match: false},
		{pattern: "?a", target: "ab", match: false},
		{pattern: "*a", target: "ab", match: false},
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("pattern_%s_target_%s", tc.pattern, tc.target)
		if tc.match {
			name += "_should_match"
		} else {
			name += "_should_not_match"
		}

		t.Run(name, func(t *testing.T) {
			match := matchAcceptEnvPattern(tc.pattern, tc.target)
			if match != tc.match {
				t.Errorf("got %v, want %v", match, tc.match)
			}
		})
	}
}

func TestFilterEnv(t *testing.T) {
	testCases := []struct {
		name             string
		acceptEnv        []string
		environ          []string
		expectedFiltered []string
		wantErrMessage   string
	}{
		{
			name:             "simple-direct-matches",
			acceptEnv:        []string{"FOO", "FOO2", "FOO_3"},
			environ:          []string{"FOO=BAR", "FOO2=BAZ", "FOO_3=123", "FOOOO4-2=AbCdEfG"},
			expectedFiltered: []string{"FOO=BAR", "FOO2=BAZ", "FOO_3=123"},
		},
		{
			name:             "bare-wildcard",
			acceptEnv:        []string{"*"},
			environ:          []string{"FOO=BAR", "FOO2=BAZ", "FOO_3=123", "FOOOO4-2=AbCdEfG"},
			expectedFiltered: []string{"FOO=BAR", "FOO2=BAZ", "FOO_3=123", "FOOOO4-2=AbCdEfG"},
		},
		{
			name:             "complex-matches",
			acceptEnv:        []string{"FO?", "FOOO*", "FO*5?7"},
			environ:          []string{"FOO=BAR", "FOO2=BAZ", "FOO_3=123", "FOOOO4-2=AbCdEfG", "FO1-kmndGamc79567=ABC", "FO57=BAR2"},
			expectedFiltered: []string{"FOO=BAR", "FOOOO4-2=AbCdEfG", "FO1-kmndGamc79567=ABC"},
		},
		{
			name:             "environ-format-invalid",
			acceptEnv:        []string{"FO?", "FOOO*", "FO*5?7"},
			environ:          []string{"FOOBAR"},
			expectedFiltered: nil,
			wantErrMessage:   `invalid environment variable: "FOOBAR". Variables must be in "KEY=VALUE" format`,
		},
		{
			name:             "ld-preload-rejected-with-wildcard",
			acceptEnv:        []string{"*"},
			environ:          []string{"LD_PRELOAD=/tmp/evil.so", "TERM=xterm"},
			expectedFiltered: []string{"TERM=xterm"},
		},
		{
			name:             "ld-vars-rejected-with-wildcard",
			acceptEnv:        []string{"*"},
			environ:          []string{"LD_PRELOAD=/tmp/evil.so", "LD_LIBRARY_PATH=/tmp", "LD_AUDIT=/tmp/audit.so", "SAFE_VAR=ok"},
			expectedFiltered: []string{"SAFE_VAR=ok"},
		},
		{
			name:             "ld-vars-rejected-with-explicit-match",
			acceptEnv:        []string{"LD_PRELOAD", "LD_LIBRARY_PATH"},
			environ:          []string{"LD_PRELOAD=/tmp/evil.so", "LD_LIBRARY_PATH=/tmp"},
			expectedFiltered: nil,
		},
		{
			name:             "ld-vars-rejected-with-prefix-pattern",
			acceptEnv:        []string{"LD_*"},
			environ:          []string{"LD_PRELOAD=/tmp/evil.so", "LD_LIBRARY_PATH=/tmp"},
			expectedFiltered: nil,
		},
		{
			name:             "ld-vars-case-insensitive",
			acceptEnv:        []string{"*"},
			environ:          []string{"ld_preload=/tmp/evil.so", "Ld_Library_Path=/tmp", "SAFE=ok"},
			expectedFiltered: []string{"SAFE=ok"},
		},
		{
			name:             "dyld-vars-rejected",
			acceptEnv:        []string{"*"},
			environ:          []string{"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib", "DYLD_LIBRARY_PATH=/tmp", "TERM=xterm"},
			expectedFiltered: []string{"TERM=xterm"},
		},
		{
			// A forwarded key containing the "," allowlist separator must be
			// rejected, since it would otherwise inject extra "su -w" entries.
			name:             "comma-in-key-rejected",
			acceptEnv:        []string{"*"},
			environ:          []string{"A,B=x", "GOOD=1"},
			expectedFiltered: []string{"GOOD=1"},
		},
		{
			name:             "empty-key-rejected",
			acceptEnv:        []string{"*"},
			environ:          []string{"=x", "GOOD=1"},
			expectedFiltered: []string{"GOOD=1"},
		},
		{
			// GOTRACEBACK controls crash tracebacks/core dumps of the
			// privileged incubator child, which could leak secrets
			name:             "gotraceback-rejected",
			acceptEnv:        []string{"*"},
			environ:          []string{"GOTRACEBACK=crash", "TERM=xterm"},
			expectedFiltered: []string{"TERM=xterm"},
		},
		{
			// glibc lookup-path variables can load attacker-controlled files
			// (e.g. gconv modules) into privileged processes; the resolver
			// variables redirect privileged lookups.
			name:      "glibc-and-resolver-vars-rejected",
			acceptEnv: []string{"*"},
			environ: []string{
				"GCONV_PATH=/tmp/evil",
				"LOCPATH=/tmp/evil",
				"NLSPATH=/tmp/evil/%N",
				"HOSTALIASES=/tmp/aliases",
				"RES_OPTIONS=attempts:1",
				"TERM=xterm",
			},
			expectedFiltered: []string{"TERM=xterm"},
		},
		{
			name:             "nul-in-name-rejected",
			acceptEnv:        []string{"*"},
			environ:          []string{"A\x00B=x", "GOOD=1"},
			expectedFiltered: []string{"GOOD=1"},
		},
		{
			name:             "nul-in-value-rejected",
			acceptEnv:        []string{"*"},
			environ:          []string{"GOOD=a\x00b"},
			expectedFiltered: nil,
		},
		{
			// Key names are closed to a known charset: spaces, control
			// chars, punctuation other than '-' and non-ASCII are rejected.
			name:             "key-charset-restricted",
			acceptEnv:        []string{"*"},
			environ:          []string{"MY VAR=1", "WEIRD\tNAME=2", "MY.VAR=3", "MY-VAR=ok", "B\xc3\xa4R=5", "MY_VAR=ok2"},
			expectedFiltered: []string{"MY-VAR=ok", "MY_VAR=ok2"},
		},
		{
			// Names are capped at 256 bytes, even when the pattern would
			// match: real names are short, longer ones only tie up the
			// matcher or bloat the child's "su -w" allowlist.
			name:             "oversized-name-rejected",
			acceptEnv:        []string{"*"},
			environ:          []string{strings.Repeat("A", maxAcceptEnvNameLen) + "=x", strings.Repeat("B", maxAcceptEnvNameLen+1) + "=x", "GOOD=1"},
			expectedFiltered: []string{strings.Repeat("A", maxAcceptEnvNameLen) + "=x", "GOOD=1"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filtered, err := filterEnv(tc.acceptEnv, tc.environ)
			if err == nil && tc.wantErrMessage != "" {
				t.Errorf("wanted error with message %q but error was nil", tc.wantErrMessage)
			}

			if err != nil && err.Error() != tc.wantErrMessage {
				t.Errorf("err = %v; want %v", err, tc.wantErrMessage)
			}

			if diff := cmp.Diff(tc.expectedFiltered, filtered); diff != "" {
				t.Errorf("unexpected filter result (-got,+want): \n%s", diff)
			}
		})
	}
}

// naiveMatchAcceptEnvPattern is a straightforward backtracking reference
// implementation of the acceptEnv wildcard semantics, used to cross-check
// matchAcceptEnvPattern.
func naiveMatchAcceptEnvPattern(pattern, target string) bool {
	if pattern == "" {
		return target == ""
	}
	switch pattern[0] {
	case '*':
		for i := 0; i <= len(target); i++ {
			if naiveMatchAcceptEnvPattern(pattern[1:], target[i:]) {
				return true
			}
		}
		return false
	case '?':
		return len(target) >= 1 && naiveMatchAcceptEnvPattern(pattern[1:], target[1:])
	default:
		return len(target) >= 1 && pattern[0] == target[0] && naiveMatchAcceptEnvPattern(pattern[1:], target[1:])
	}
}

// TestMatchAcceptEnvPatternAgainstNaive checks matchAcceptEnvPattern against a
// naive backtracking reference matcher over random patterns and targets.
func TestMatchAcceptEnvPatternAgainstNaive(t *testing.T) {
	// Patterns and targets are built from an alphabet containing literals,
	// the wildcard characters themselves (as literals in the target), and a
	// separator that commonly follows '*'s in acceptEnv patterns.
	alphabet := []string{"a", "b", "_", "?", "*", "T"}

	rnd := rand.New(rand.NewPCG(1, 2))
	gen := func(maxLen int) string {
		n := rnd.IntN(maxLen + 1)
		var sb strings.Builder
		for range n {
			sb.WriteString(alphabet[rnd.IntN(len(alphabet))])
		}
		return sb.String()
	}

	for range 5000 {
		pattern, target := gen(12), gen(20)
		want := naiveMatchAcceptEnvPattern(pattern, target)
		if got := matchAcceptEnvPattern(pattern, target); got != want {
			t.Fatalf("matchAcceptEnvPattern(%q, %q) = %v; want %v", pattern, target, got, want)
		}
	}
}

// TestMatchAcceptEnvPatternNoBacktrackingBlowup is a timing regression test:
// the recursive matcher took ~2.7s on this input at n=400. The iterative
// matcher must stay far below a generous bound.
func TestMatchAcceptEnvPatternNoBacktrackingBlowup(t *testing.T) {
	pattern := "TS_*_*_*_*_*_TOKEN"
	// No "TOKEN" suffix, so every '*' combination must be tried, but with
	// many '_' separators for the '*'s to fan out over.
	target := "TS_" + strings.Repeat("a_", 198) + "a"
	if len(target) != 400 {
		t.Fatalf("target len = %d, want 400", len(target))
	}

	start := time.Now()
	got := matchAcceptEnvPattern(pattern, target)
	elapsed := time.Since(start)

	if got {
		t.Errorf("matchAcceptEnvPattern(%q, %q) = true; want false", pattern, target)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("matchAcceptEnvPattern took %v; want < 100ms", elapsed)
	}
	t.Logf("matched %d-byte target in %v", len(target), elapsed)
}
