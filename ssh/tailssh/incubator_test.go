// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"slices"
	"strings"
	"testing"

	gliderssh "github.com/tailscale/gliderssh"
	"golang.org/x/sys/unix"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/logger"
)

func TestMergeForwardedEnv(t *testing.T) {
	defaults := []string{
		"TERM=dumb",
		"LANG=C",
		"LC_TIME=C",
		"TERM=xterm-256color",
		"LANG=en_US.UTF-8",
		"LC_TIME=en_US.UTF-8",
		"HOME=/ignored",
	}
	for _, policyTerm := range []string{"", "policy-term"} {
		var forwarded []string
		wantTerm := "xterm-256color"
		if policyTerm != "" {
			forwarded = []string{"TERM=" + policyTerm}
			wantTerm = policyTerm
		}
		got := mergeForwardedEnv(defaults, forwarded)
		want := []string{"TERM=" + wantTerm, "LANG=en_US.UTF-8", "LC_TIME=en_US.UTF-8"}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("mergeForwardedEnv = %q; want %q", got, want)
		}
	}
}

// fakeSession is a minimal gliderssh.Session for exercising the incubator
// command/env construction. Only the methods used by newIncubatorCommand and
// incubatorEnv are implemented; the embedded interface is nil, so any other
// method call panics and catches unexpected use.
type fakeSession struct {
	gliderssh.Session
	rawCommand string
	subsystem  string
	environ    []string
}

func (s fakeSession) RawCommand() string { return s.rawCommand }
func (s fakeSession) Subsystem() string  { return s.subsystem }
func (s fakeSession) Environ() []string  { return s.environ }
func (s fakeSession) Pty() (gliderssh.Pty, <-chan gliderssh.Window, bool) {
	return gliderssh.Pty{}, nil, false
}

// newTestSession builds an sshSession wired to the localState fake, with the
// NodeAttrSSHEnvironmentVariables capability enabled and the given acceptEnv
// policy, so newIncubatorCommand exercises the env-forwarding path.
func newTestSession(t *testing.T, acceptEnv []string, clientEnviron []string) *sshSession {
	t.Helper()
	srv := &server{
		logf: logger.Discard,
		lb: &localState{
			sshEnabled: true,
			caps:       []nodecap.Cap{nodecap.SSHEnvironmentVariables},
		},
		// tailscaledPath must be non-empty to take the incubator (be-child)
		// path rather than the direct-exec fallback.
		tailscaledPath: "/usr/sbin/tailscaled",
	}
	c := &conn{
		srv:       srv,
		acceptEnv: acceptEnv,
		info: &sshConnInfo{
			sshUser: "alice",
			src:     netip.MustParseAddrPort("100.100.100.101:2222"),
			dst:     netip.MustParseAddrPort("100.100.100.102:22"),
			node:    (&tailcfg.Node{}).View(),
		},
		localUser:    &userMeta{User: user.User{Username: "alice", Uid: "1000", Gid: "1000", HomeDir: "/home/alice"}},
		userGroupIDs: []string{"1000"},
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	return &sshSession{
		Session: fakeSession{environ: clientEnviron},
		conn:    c,
		ctx:     ctx,
	}
}

// TestForwardedEnvSecretNotOnArgv is the core security regression test for the
// acceptEnv secret leak: a forwarded value must be returned for delivery via
// an inherited file, and must appear neither on the command line (cmd.Args,
// logged at session start and visible in /proc/<pid>/cmdline) nor in the
// privileged child's environment (see incubatorEnv).
func TestForwardedEnvSecretNotOnArgv(t *testing.T) {
	const secret = "s3cr3t-token-value"
	ss := newTestSession(t,
		[]string{"GITLAB_API_TOKEN"},
		[]string{"GITLAB_API_TOKEN=" + secret, "IGNORED=nope"},
	)

	cmd, forwardedEnv, err := ss.newIncubatorCommand(logger.Discard)
	if err != nil {
		t.Fatalf("newIncubatorCommand: %v", err)
	}

	// The pair must be returned for delivery via the inherited file, and the
	// argv must name the fd to read it from.
	if !slices.Contains(forwardedEnv, "GITLAB_API_TOKEN="+secret) {
		t.Errorf("forwardedEnv = %q, want it to contain the forwarded secret", forwardedEnv)
	}
	if !slices.Contains(cmd.Args, "--env-fd=3") {
		t.Errorf("cmd.Args = %q, want --env-fd=3", cmd.Args)
	}

	// Neither the secret value nor the key name may appear anywhere on the argv.
	argv := strings.Join(cmd.Args, "\x00")
	if strings.Contains(argv, secret) {
		t.Errorf("secret value leaked onto cmd.Args: %q", cmd.Args)
	}
	if strings.Contains(argv, "GITLAB_API_TOKEN") {
		t.Errorf("forwarded key name leaked onto cmd.Args: %q", cmd.Args)
	}

	// The privileged child's environment must not contain the forwarded pair.
	for _, kv := range ss.incubatorEnv() {
		if strings.Contains(kv, secret) {
			t.Errorf("forwarded pair present in child environment: %q", kv)
		}
	}
}

// TestIncubatorEnvServerOnly verifies that no client-forwarded variable enters
// the privileged child's environment, even under a wildcard acceptEnv policy:
// cmd.Env carries only server-chosen values and the client's TERM/LANG/LC_*
// (matching OpenSSH's default AcceptEnv). Forwarded pairs travel via an
// inherited file instead (see forwardedEnvFile), so even names like PATH and
// GODEBUG that are unsafe in the privileged child can still be delivered to
// the user's session.
func TestIncubatorEnvServerOnly(t *testing.T) {
	ss := newTestSession(t,
		[]string{"*"},
		[]string{
			"PATH=/client/evil",
			"HOME=/tmp/evil",
			"GODEBUG=asyncpreemptoff=1",
			"GIT_TOKEN=fromclient",
			"TERM=xterm-256color", // accepted via acceptEnvPair, not filterEnv
		},
	)
	_, forwardedEnv, err := ss.newIncubatorCommand(logger.Discard)
	if err != nil {
		t.Fatalf("newIncubatorCommand: %v", err)
	}
	env := ss.incubatorEnv()

	for _, kv := range env {
		for _, evil := range []string{"/client/evil", "/tmp/evil", "asyncpreemptoff", "fromclient"} {
			if strings.Contains(kv, evil) {
				t.Errorf("client-controlled value %q present in child environment: %q", evil, env)
			}
		}
	}
	// USER/HOME come from the server; TERM is the one client-controlled value
	// allowed in (OpenSSH parity).
	for _, want := range []string{"USER=alice", "HOME=/home/alice", "TERM=xterm-256color"} {
		if !slices.Contains(env, want) {
			t.Errorf("%q missing from child environment: %q", want, env)
		}
	}
	// filterEnv accepted the pairs for fd delivery to the user's session.
	for _, want := range []string{"GIT_TOKEN=fromclient", "GODEBUG=asyncpreemptoff=1", "PATH=/client/evil"} {
		if !slices.Contains(forwardedEnv, want) {
			t.Errorf("%q missing from forwardedEnv: %q", want, forwardedEnv)
		}
	}
}

// TestForwardedEnvFileRoundTrip verifies the parent-side payload pipe: the
// child decodes the JSON-encoded pairs from the read end, and calling it with
// nothing to forward is an error.
func TestForwardedEnvFileRoundTrip(t *testing.T) {
	if f, err := forwardedEnvFile(nil); err == nil {
		t.Fatalf("forwardedEnvFile(nil) = %v, nil; want error", f)
	}

	pairs := []string{"GITLAB_API_TOKEN=s3cr3t", "PATH=/client/bin"}
	f, err := forwardedEnvFile(pairs)
	if err != nil {
		t.Fatalf("forwardedEnvFile: %v", err)
	}

	// Dup the read end (like the child's ExtraFiles fd) and close the parent's copy
	dup, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	f.Close()
	ia := incubatorArgs{envFD: dup}
	if err := ia.loadForwardedEnv(); err != nil {
		t.Fatalf("loadForwardedEnv: %v", err)
	}
	if !slices.Equal(ia.forwardedEnv, pairs) {
		t.Errorf("forwardedEnv = %q, want %q", ia.forwardedEnv, pairs)
	}

	// forwardedEnviron applies the pairs to the user's environment (the
	// in-process, post-drop path only).
	env := ia.forwardedEnviron()
	for _, p := range pairs {
		if !slices.Contains(env, p) {
			t.Errorf("pair %q missing from forwardedEnviron env", p)
		}
	}
	// The su -w allowlist is SSH_AUTH_SOCK plus the forwarded keys. The
	// pairs ride su's own environment. See
	// TestRootExecEnvExcludesClientEnv for the TERM/LANG/LC_* exclusion
	// from that environment.
	want := []string{"SSH_AUTH_SOCK"}
	for _, p := range pairs {
		if k, _, ok := strings.Cut(p, "="); ok {
			want = append(want, k)
		}
	}
	if !slices.Equal(ia.suAllowEnvKeys(), want) {
		t.Errorf("suAllowEnvKeys() = %q; want %q", ia.suAllowEnvKeys(), want)
	}
}

// TestParseIncubatorArgsEnvFD verifies that --env-fd values naming
// stdin/stdout/stderr are rejected: a legitimate payload fd always comes from
// an ExtraFiles entry, so it is >= 3.
func TestParseIncubatorArgsEnvFD(t *testing.T) {
	if _, err := parseIncubatorArgs([]string{"--groups=1000", "--env-fd=2"}); err == nil {
		t.Errorf("--env-fd=2: got nil error, want rejection")
	}
	for _, args := range [][]string{
		{"--groups=1000", "--env-fd=3"},
		{"--groups=1000"}, // unset defaults to -1
	} {
		if _, err := parseIncubatorArgs(args); err != nil {
			t.Errorf("%v: got error %v, want nil", args, err)
		}
	}
}

// TestLoadForwardedEnvLegacyEncodedEnv covers the deprecated --encoded-env
// compatibility path: an outdated parent tailscaled passes the accepted
// environment as a quoted JSON argv flag, and the child must still decode it
// into the user's environment and the "su -w" allowlist.
func TestLoadForwardedEnvLegacyEncodedEnv(t *testing.T) {
	pairs := []string{"GITLAB_API_TOKEN=s3cr3t", "OTHER=1"}
	raw, _ := json.Marshal(pairs)
	// Exactly what an old parent puts on the argv.
	ia, err := parseIncubatorArgs([]string{"--groups=1000", "--encoded-env=" + fmt.Sprintf("%q", raw)})
	if err != nil {
		t.Fatalf("parseIncubatorArgs: %v", err)
	}
	if err := ia.loadForwardedEnv(); err != nil {
		t.Fatalf("loadForwardedEnv: %v", err)
	}
	if !slices.Equal(ia.forwardedEnv, pairs) {
		t.Errorf("forwardedEnv = %q, want %q", ia.forwardedEnv, pairs)
	}

	env := ia.forwardedEnviron()
	for _, p := range pairs {
		if !slices.Contains(env, p) {
			t.Errorf("legacy pair %q missing from env", p)
		}
	}
	// The su -w allowlist names only the pairs that were forwarded plus
	// the server-derived SSH_AUTH_SOCK.
	empty := incubatorArgs{}
	if keys := empty.suAllowEnvKeys(); !slices.Equal(keys, []string{"SSH_AUTH_SOCK"}) {
		t.Errorf("suAllowEnvKeys() with no forwarded pairs = %q; want [SSH_AUTH_SOCK]", keys)
	}

	// Malformed values are rejected.
	bad := incubatorArgs{encodedEnv: "%q-not-json"}
	if err := bad.loadForwardedEnv(); err == nil {
		t.Errorf("malformed encodedEnv: got nil error")
	}
}

// TestLoadForwardedEnvSanitizesPairs verifies the child-side integrity check:
// pairs that would corrupt the "su -w" allowlist (empty or comma-carrying
// names), truncate on exec (NUL bytes), or are dangerous env vars (which a
// new parent also rejects in filterEnv) are dropped when the payload is
// loaded, even though a new parent would never send them.
func TestLoadForwardedEnvSanitizesPairs(t *testing.T) {
	pairs := []string{
		"GOOD=1", "A,B=x", "C\x00D=2", "E=3\x004", "=x", "malformed", "MY VAR=6", "MY.VAR=7",
		"LD_PRELOAD=/tmp/evil.so", "gconv_path=/tmp/evil", "RES_OPTIONS=attempts:1",
	}
	raw, _ := json.Marshal(pairs)
	ia, err := parseIncubatorArgs([]string{"--groups=1000", "--encoded-env=" + fmt.Sprintf("%q", raw)})
	if err != nil {
		t.Fatalf("parseIncubatorArgs: %v", err)
	}
	if err := ia.loadForwardedEnv(); err != nil {
		t.Fatalf("loadForwardedEnv: %v", err)
	}
	if !slices.Equal(ia.forwardedEnv, []string{"GOOD=1"}) {
		t.Errorf("forwardedEnv = %q, want [GOOD=1]", ia.forwardedEnv)
	}
}

// TestRootExecEnvExcludesClientEnv is the structural env regression
// test: the environment handed to root-exec'd login/su contains no
// client-derived pair, neither the acceptEnvPair set, the only
// client-controllable keys in the incubator's environment, nor
// anything from the forwarded env, while the post-drop environment
// from forwardedEnviron carries everything for the user's own session.
func TestRootExecEnvExcludesClientEnv(t *testing.T) {
	ia := incubatorArgs{forwardedEnv: []string{
		"GITLAB_API_TOKEN=s3cr3t",
		"LANG=xx_YY.UTF-8",
		"LC_ALL=xx_YY.UTF-8",
	}}
	// The incubator's own environment is built by tailscaled (incubatorEnv:
	// SHELL/USER/HOME/PATH/SSH_*, the server-set agent socket, and the
	// client's acceptEnvPair'd pairs), so the test process's ambient
	// TERM/LANG (if any) stands in for the client-derived ones. A daemon
	// or root environment must never supply them to the user's process:
	// they flow only through the forwarded pairs.
	t.Setenv("TERM", "rootenv-xterm-256color")
	root := ia.rootExecEnviron()
	if len(root) == 0 && len(os.Environ()) > 0 {
		t.Fatal("rootExecEnviron() = empty; want the server-derived environment")
	}
	for _, kv := range root {
		k, _, _ := strings.Cut(kv, "=")
		if clientDerivedEnvKey(k) {
			t.Errorf("client-derived pair %q present in root-exec'd environment", kv)
		}
	}
	// Every forwarded pair (secret or not) is absent from the root env but
	// present in the post-drop env.
	for _, pair := range ia.forwardedEnv {
		if slices.Contains(root, pair) {
			t.Errorf("forwarded pair %q present in root-exec'd environment", pair)
		}
	}
	user := ia.forwardedEnviron()
	for _, pair := range ia.forwardedEnv {
		if !slices.Contains(user, pair) {
			t.Errorf("forwarded pair %q missing from post-drop environment", pair)
		}
	}
	// The post-drop environment takes TERM/LANG/LC_* only from the
	// forwarded pairs: the ambient daemon-side TERM must not leak, and a
	// client-derived key the client did not send stays absent.
	got := map[string]string{}
	for _, kv := range user {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if v, ok := got["TERM"]; ok {
		t.Errorf("post-drop environment has TERM=%q; client sent none", v)
	}
	if got["LANG"] != "xx_YY.UTF-8" || got["LC_ALL"] != "xx_YY.UTF-8" {
		t.Errorf("post-drop locale = LANG=%q LC_ALL=%q; want forwarded values",
			got["LANG"], got["LC_ALL"])
	}
	for _, k := range []string{"TERM", "LANG", "LC_ALL"} {
		if !clientDerivedEnvKey(k) {
			t.Errorf("clientDerivedEnvKey(%q) = false; want true", k)
		}
	}
	for _, k := range []string{"HOME", "PATH", "SSH_CONNECTION", "SSH_AUTH_SOCK", "USER"} {
		if clientDerivedEnvKey(k) {
			t.Errorf("clientDerivedEnvKey(%q) = true; want false (server-derived)", k)
		}
	}
	// findSU's capability probe runs su as root too, and its
	// environment must obey the same contract.
	probe := suProbeCmd(ia, "/bin/su")
	if len(probe.Env) == 0 && len(os.Environ()) > 0 {
		t.Fatal("suProbeCmd env = empty; want the filtered root-exec environment")
	}
	for _, kv := range probe.Env {
		if k, _, _ := strings.Cut(kv, "="); clientDerivedEnvKey(k) {
			t.Errorf("client-derived pair %q present in findSU probe environment", kv)
		}
	}
}

// TestDirectExecRootFallbackRefused verifies that the direct-exec fallback
// (no tailscaledPath) refuses to run a non-root local user's session when
// tailscaled runs as root, since without the be-child incubator there is no
// privilege drop and the session would run as root.
func TestDirectExecRootFallbackRefused(t *testing.T) {
	for _, tt := range []struct {
		name string
		euid int
		uid  string
		want bool
	}{
		{name: "root-euid-root-user", euid: 0, uid: "0", want: true},
		{name: "root-euid-noncanonical-root-user", euid: 0, uid: "00", want: true},
		{name: "root-euid-non-root-user", euid: 0, uid: "1000", want: false},
		{name: "non-root-euid", euid: 1000, uid: "1000", want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lu := &userMeta{User: user.User{Username: "alice", Uid: tt.uid, Gid: tt.uid}}
			if got := directExecAllowed(tt.euid, lu); got != tt.want {
				t.Errorf("directExecAllowed(euid=%d, uid=%s) = %v; want %v", tt.euid, tt.uid, got, tt.want)
			}
		})
	}

	// Wiring: as root, the direct-exec fallback must refuse the session
	// for the non-root local user (newTestSession's alice is uid 1000).
	if os.Geteuid() == 0 {
		ss := newTestSession(t, nil, nil)
		ss.conn.srv.tailscaledPath = ""
		if _, _, err := ss.newIncubatorCommand(logger.Discard); err == nil {
			t.Error("newIncubatorCommand (direct exec, root euid, non-root local user) = nil error; want refusal")
		}
	}
}
