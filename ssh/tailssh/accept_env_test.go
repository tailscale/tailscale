// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/logger"
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
		{"gotraceback", true},
		{"TERM", false},
		{"LANG", false},
		{"LC_ALL", false},
		{"PATH", false},
		{"HOME", false},
		{"LDFLAGS", false},
		{"MY_LD_PRELOAD", false},
		{"GOTRACEBACK_SUFFIX", false},
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
			// A forwarded key containing the "," separator of the "su -w"
			// allowlist must be rejected, since it would otherwise inject
			// extra entries into that allowlist.
			name:             "comma-in-key-rejected",
			acceptEnv:        []string{"*"},
			environ:          []string{"A,B=x", "GOOD=1"},
			expectedFiltered: []string{"GOOD=1"},
		},
		{
			// Even an explicit (non-wildcard) allowlist entry cannot override
			// the structural name rules.
			name:             "comma-in-key-rejected-explicit-match",
			acceptEnv:        []string{"A,B"},
			environ:          []string{"A,B=x", "TERM=xterm"},
			expectedFiltered: nil,
		},
		{
			name:             "empty-key-rejected",
			acceptEnv:        []string{"*"},
			environ:          []string{"=orphan", "GOOD=1"},
			expectedFiltered: []string{"GOOD=1"},
		},
		{
			name:             "whitespace-and-control-keys-rejected",
			acceptEnv:        []string{"*"},
			environ:          []string{"A B=x", "A\tB=x", "A\x00B=x", "A\nB=x", "GOOD=1"},
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

func TestValidEnvName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"FOO", true},
		{"FOO_BAR2", true},
		{"lower_case", true},
		{"weird-but-fine.name", true},
		{"", false},
		// "=" would make the KEY=VALUE encoding ambiguous.
		{"FOO=BAR", false},
		// "," is the separator of the "su -w" allowlist the incubator builds
		// from these names, so it could inject extra entries.
		{"FOO,BAR", false},
		{",", false},
		{"FOO BAR", false},
		{"FOO\tBAR", false},
		{"FOO\nBAR", false},
		{"FOO\x00BAR", false},
		{"FOO\x1bBAR", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.name), func(t *testing.T) {
			if got := validEnvName(tt.name); got != tt.want {
				t.Errorf("validEnvName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestForwardedEnvPipeRoundTrip covers the whole parent->child transport: the
// parent writes the payload to a pipe, and the child reads it back off the
// file descriptor it was handed.
func TestForwardedEnvPipeRoundTrip(t *testing.T) {
	acceptEnv := []string{"GIT_*", "EXACT_MATCH"}
	env := []string{"GIT_TOKEN=s3cr3t", "EXACT_MATCH=yes"}

	f, err := forwardedEnvFile(logger.Discard, acceptEnv, env)
	if err != nil {
		t.Fatalf("forwardedEnvFile: %v", err)
	}
	defer f.Close()

	got, err := receiveForwardedEnv(f)
	if err != nil {
		t.Fatalf("receiveForwardedEnv: %v", err)
	}
	if !slices.Equal(got, env) {
		t.Errorf("round trip = %q, want %q", got, env)
	}
}

// TestForwardedEnvFileEmpty checks that an empty payload round trips cleanly
// rather than erroring, since JSON omits both fields in that case.
func TestForwardedEnvFileEmpty(t *testing.T) {
	f, err := forwardedEnvFile(logger.Discard, nil, nil)
	if err != nil {
		t.Fatalf("forwardedEnvFile: %v", err)
	}
	defer f.Close()
	got, err := receiveForwardedEnv(f)
	if err != nil {
		t.Fatalf("receiveForwardedEnv: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %q, want nothing", got)
	}
}

func TestForwardedEnvFileTooLarge(t *testing.T) {
	// Over the per-entry limit: rejected by name, and the error must not
	// contain the value.
	huge := strings.Repeat("x", maxForwardedEnvEntry+1)
	f, err := forwardedEnvFile(logger.Discard, []string{"*"}, []string{"BIG=" + huge})
	if err == nil {
		f.Close()
		t.Fatal("forwardedEnvFile succeeded, want error")
	}
	if !strings.Contains(err.Error(), `"BIG"`) || strings.Contains(err.Error(), huge) {
		t.Errorf("err = %v, want it to name BIG without quoting the value", err)
	}

	// Under the per-entry limit but over the total.
	var many []string
	for i := 0; len(many)*100000 < maxForwardedEnvSize+100000; i++ {
		many = append(many, fmt.Sprintf("V%d=%s", i, strings.Repeat("x", 100000)))
	}
	f, err = forwardedEnvFile(logger.Discard, []string{"*"}, many)
	if err == nil {
		f.Close()
		t.Fatal("forwardedEnvFile succeeded on oversized total, want error")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("err = %v, want a size error", err)
	}
}

// TestForwardedEnvEntryLimitMatchesExecve pins the per-entry limit to the
// kernel constant it exists for: Linux MAX_ARG_STRLEN is 32 pages, and execve
// returns E2BIG for any single environment entry above it. Accepting more here
// would just move the failure to the exec of su or login.
func TestForwardedEnvEntryLimitMatchesExecve(t *testing.T) {
	if maxForwardedEnvEntry > 131072 {
		t.Errorf("maxForwardedEnvEntry = %d, must not exceed MAX_ARG_STRLEN (131072)", maxForwardedEnvEntry)
	}
}

// TestReceiveForwardedEnvRejectsOversizedEntry checks the child applies the
// same size rule, so a parent bug cannot hand it something execve will refuse.
func TestReceiveForwardedEnvRejectsOversizedEntry(t *testing.T) {
	b, err := json.Marshal(forwardedEnvPayload{
		AcceptEnv: []string{"*"},
		Env:       []string{"BIG=" + strings.Repeat("x", maxForwardedEnvEntry+1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiveForwardedEnv(bytes.NewReader(b)); err == nil {
		t.Fatal("got nil error, want failure")
	} else if !strings.Contains(err.Error(), `"BIG"`) {
		t.Errorf("err = %v, want it to name the offending variable", err)
	}
}

// TestReceiveForwardedEnvTruncated covers the failure mode of a parent whose
// write was cut short (see forwardedEnvFile's deadline): the child must fail
// closed, and the error must be diagnosable as a short read rather than
// looking like arbitrary corruption.
func TestReceiveForwardedEnvTruncated(t *testing.T) {
	full, err := json.Marshal(forwardedEnvPayload{AcceptEnv: []string{"*"}, Env: []string{"A=1", "B=2"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = receiveForwardedEnv(bytes.NewReader(full[:len(full)/2]))
	if err == nil {
		t.Fatal("got nil error, want failure")
	}
	for _, want := range []string{"truncated", "bytes read"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q", err, want)
		}
	}
}

// TestReceiveForwardedEnvEnforcesPolicy is the child-side trust boundary test:
// the incubator re-runs the acceptEnv filter on whatever it is handed, so a
// parent that (through a bug, or because it is a different, older binary) sends
// pairs the policy does not allow cannot widen what the incubator forwards.
func TestReceiveForwardedEnvEnforcesPolicy(t *testing.T) {
	tests := []struct {
		name    string
		payload forwardedEnvPayload
		want    []string
	}{
		{
			name: "not-matching-policy-dropped",
			payload: forwardedEnvPayload{
				AcceptEnv: []string{"GIT_*"},
				Env:       []string{"GIT_TOKEN=ok", "SOMETHING_ELSE=nope"},
			},
			want: []string{"GIT_TOKEN=ok"},
		},
		{
			name: "dangerous-dropped-even-if-policy-allows",
			payload: forwardedEnvPayload{
				AcceptEnv: []string{"*"},
				Env:       []string{"LD_PRELOAD=/tmp/evil.so", "GOTRACEBACK=crash", "SAFE=ok"},
			},
			want: []string{"SAFE=ok"},
		},
		{
			name: "invalid-names-dropped",
			payload: forwardedEnvPayload{
				AcceptEnv: []string{"*"},
				Env:       []string{"A,B=inject", "SAFE=ok"},
			},
			want: []string{"SAFE=ok"},
		},
		{
			name: "empty-policy-accepts-nothing",
			payload: forwardedEnvPayload{
				Env: []string{"ANYTHING=nope"},
			},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			got, err := receiveForwardedEnv(bytes.NewReader(b))
			if err != nil {
				t.Fatalf("receiveForwardedEnv: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReceiveForwardedEnvErrors checks that a malformed payload fails the
// session rather than being silently ignored: the incubator must not guess at
// an environment it could not parse.
func TestReceiveForwardedEnvErrors(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		wantErr string
	}{
		{"not-json", []byte("this is not json"), "parsing forwarded environment"},
		{"truncated", []byte(`{"env":["A=1"`), "parsing forwarded environment"},
		{"wrong-shape", []byte(`{"env":"A=1"}`), "parsing forwarded environment"},
		{
			name:    "malformed-pair",
			in:      []byte(`{"acceptEnv":["*"],"env":["NO_EQUALS_SIGN"]}`),
			wantErr: "filtering forwarded environment",
		},
		{
			name:    "oversize",
			in:      append([]byte(`{"env":["A=`), append(bytes.Repeat([]byte("x"), maxForwardedEnvSize), []byte(`"]}`)...)...),
			wantErr: "too large",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := receiveForwardedEnv(bytes.NewReader(tc.in))
			if err == nil {
				t.Fatal("got nil error, want failure")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestReceiveForwardedEnvReadError makes sure a failure to read the descriptor
// (rather than to parse it) is also fatal.
func TestReceiveForwardedEnvReadError(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	r.Close() // reading from a closed file fails
	if _, err := receiveForwardedEnv(r); err == nil {
		t.Fatal("got nil error, want failure")
	}
}

func TestMergeForwardedEnv(t *testing.T) {
	tests := []struct {
		name      string
		environ   []string
		forwarded []string
		wantEnv   []string
		wantKeys  []string
	}{
		{
			name:      "nothing-forwarded",
			environ:   []string{"PATH=/bin", "HOME=/home/u"},
			forwarded: nil,
			wantEnv:   []string{"PATH=/bin", "HOME=/home/u"},
			wantKeys:  nil,
		},
		{
			name:      "appended-in-order",
			environ:   []string{"PATH=/bin"},
			forwarded: []string{"B=2", "A=1"},
			wantEnv:   []string{"PATH=/bin", "B=2", "A=1"},
			wantKeys:  []string{"B", "A"},
		},
		{
			// The server-set values belong to the still-privileged parent's
			// idea of the session; a client must not be able to replace them.
			name:      "server-values-win",
			environ:   []string{"PATH=/server/bin", "HOME=/home/u", "SSH_AUTH_SOCK=/server/sock"},
			forwarded: []string{"PATH=/client/evil", "HOME=/tmp/evil", "SSH_AUTH_SOCK=/client/sock", "TOKEN=secret"},
			wantEnv:   []string{"PATH=/server/bin", "HOME=/home/u", "SSH_AUTH_SOCK=/server/sock", "TOKEN=secret"},
			wantKeys:  []string{"TOKEN"},
		},
		{
			// A duplicate name must not appear twice in the "su -w" allowlist.
			name:      "duplicates-first-wins",
			environ:   []string{"PATH=/bin"},
			forwarded: []string{"TOKEN=first", "TOKEN=second"},
			wantEnv:   []string{"PATH=/bin", "TOKEN=first"},
			wantKeys:  []string{"TOKEN"},
		},
		{
			name:      "malformed-forwarded-dropped",
			environ:   []string{"PATH=/bin"},
			forwarded: []string{"NO_EQUALS", "OK=1"},
			wantEnv:   []string{"PATH=/bin", "OK=1"},
			wantKeys:  []string{"OK"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotEnv, gotKeys := mergeForwardedEnv(slices.Clone(tc.environ), tc.forwarded)
			if diff := cmp.Diff(tc.wantEnv, gotEnv); diff != "" {
				t.Errorf("env (-want,+got):\n%s", diff)
			}
			if !slices.Equal(gotKeys, tc.wantKeys) {
				t.Errorf("keys = %q, want %q", gotKeys, tc.wantKeys)
			}
		})
	}
}

// TestParseLegacyEncodedEnv covers the deprecated --encoded-env path that only
// exists for an outdated parent tailscaled. The policy is not available there,
// but the policy-independent rules are still applied, since an old parent's
// copy of them may be missing entries added since.
func TestParseLegacyEncodedEnv(t *testing.T) {
	quote := func(s string) string { return strconv.Quote(s) }

	tests := []struct {
		name    string
		encoded string
		want    []string
		wantErr bool
	}{
		{
			name:    "simple",
			encoded: quote(`["FOO=bar","BAZ=qux"]`),
			want:    []string{"FOO=bar", "BAZ=qux"},
		},
		{
			name:    "empty-array",
			encoded: quote(`[]`),
			want:    nil,
		},
		{
			name:    "dangerous-dropped",
			encoded: quote(`["LD_PRELOAD=/tmp/evil.so","GOTRACEBACK=crash","FOO=bar"]`),
			want:    []string{"FOO=bar"},
		},
		{
			name:    "invalid-names-dropped",
			encoded: quote(`["A,B=inject","=orphan","NO_EQUALS","FOO=bar"]`),
			want:    []string{"FOO=bar"},
		},
		{
			name:    "not-quoted",
			encoded: `["FOO=bar"]`,
			wantErr: true,
		},
		{
			name:    "not-json",
			encoded: quote(`nonsense`),
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLegacyEncodedEnv(tc.encoded)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLegacyEncodedEnv: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
