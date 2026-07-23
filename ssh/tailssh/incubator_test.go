// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"context"
	"net/netip"
	"os/user"
	"slices"
	"strings"
	"testing"

	gliderssh "github.com/tailscale/gliderssh"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

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
			caps:       []tailcfg.NodeCapability{tailcfg.NodeAttrSSHEnvironmentVariables},
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
// acceptEnv secret leak: a forwarded value must be delivered via the child's
// environment (cmd.Env) and must appear nowhere on the command line (cmd.Args),
// which is logged at session start and visible in /proc/<pid>/cmdline. Neither
// the value nor the (potentially sensitive) key name may appear on the argv;
// the key names travel via the allowedEnvKeysEnv environment variable instead.
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

	// The value must be returned for delivery via the environment...
	if !slices.Contains(forwardedEnv, "GITLAB_API_TOKEN="+secret) {
		t.Errorf("forwardedEnv = %q, want it to contain the forwarded secret", forwardedEnv)
	}
	// ...and it must end up in the child's actual environment, together with
	// the allowedEnvKeysEnv entry naming the forwarded key.
	env := ss.incubatorEnv(forwardedEnv)
	if !slices.Contains(env, "GITLAB_API_TOKEN="+secret) {
		t.Errorf("incubatorEnv did not contain the forwarded secret; got %q", env)
	}
	if !slices.Contains(env, allowedEnvKeysEnv+"=GITLAB_API_TOKEN") {
		t.Errorf("incubatorEnv did not carry the key name via %s; got %q", allowedEnvKeysEnv, env)
	}

	// Neither the secret value nor the key name may appear anywhere on the argv.
	argv := strings.Join(cmd.Args, "\x00")
	if strings.Contains(argv, secret) {
		t.Errorf("secret value leaked onto cmd.Args: %q", cmd.Args)
	}
	if strings.Contains(argv, "GITLAB_API_TOKEN") {
		t.Errorf("forwarded key name leaked onto cmd.Args: %q", cmd.Args)
	}
}

// TestForwardedEnvKeysSpoofRejected checks the trust boundary end-to-end: a
// client that tries to forward the parent->child bookkeeping variable
// (allowedEnvKeysEnv), or a key containing the "," allowlist separator, under a
// wildcard acceptEnv policy must not be able to inject entries into the
// incubator's env. filterEnv drops both, so newIncubatorCommand never forwards
// them and the only allowedEnvKeysEnv entry in the child env is the one the
// parent set for the legitimately-accepted keys.
func TestForwardedEnvKeysSpoofRejected(t *testing.T) {
	ss := newTestSession(t,
		[]string{"*"}, // permissive policy: the worst case for spoofing
		[]string{
			allowedEnvKeysEnv + "=EVIL1,EVIL2", // name collision attempt
			"A,B=x",                            // comma-in-key injection attempt
			"LEGIT=ok",                         // a genuinely accepted var
		},
	)

	_, forwardedEnv, err := ss.newIncubatorCommand(logger.Discard)
	if err != nil {
		t.Fatalf("newIncubatorCommand: %v", err)
	}

	// Only the legitimate variable is forwarded; neither spoof survives filtering.
	if !slices.Contains(forwardedEnv, "LEGIT=ok") {
		t.Errorf("forwardedEnv = %q, want it to contain LEGIT=ok", forwardedEnv)
	}
	for _, kv := range forwardedEnv {
		if k, _, _ := strings.Cut(kv, "="); reservedEnvKey(k) {
			t.Errorf("reserved/injecting key %q was forwarded: %q", k, forwardedEnv)
		}
	}

	// In the assembled child env there is exactly one allowedEnvKeysEnv entry
	// (the parent's), and it names only the legitimate key.
	env := ss.incubatorEnv(forwardedEnv)
	var bookkeeping []string
	for _, kv := range env {
		if k, _, _ := strings.Cut(kv, "="); k == allowedEnvKeysEnv {
			bookkeeping = append(bookkeeping, kv)
		}
	}
	if want := []string{allowedEnvKeysEnv + "=LEGIT"}; !slices.Equal(bookkeeping, want) {
		t.Errorf("bookkeeping entries = %q, want %q", bookkeeping, want)
	}

	// And the child-side reconstruction (stripAllowedEnvKeys, shared by both
	// platforms' forwardedEnviron) yields neither spoofed name in the su -w
	// allowlist, and strips the bookkeeping var back out entirely.
	strippedEnv, allowedKeys := stripAllowedEnvKeys(slices.Clone(env))
	for _, kv := range strippedEnv {
		if k, _, _ := strings.Cut(kv, "="); k == allowedEnvKeysEnv {
			t.Errorf("%s survived stripping: %q", allowedEnvKeysEnv, strippedEnv)
		}
	}
	for _, bad := range []string{"EVIL1", "EVIL2", "A", "B"} {
		if slices.Contains(allowedKeys, bad) {
			t.Errorf("injected key %q reached su -w allowlist %q", bad, allowedKeys)
		}
	}
	if !slices.Contains(allowedKeys, "LEGIT") {
		t.Errorf("legitimate key LEGIT missing from allowlist %q", allowedKeys)
	}
}

// TestIncubatorEnvNoReplace pins the collision rule for incubatorEnv: a
// client-forwarded variable whose key collides with a server-set value (PATH,
// HOME, USER, SHELL, SSH_CLIENT, ...) is dropped. Dropped keys are also
// omitted from the allowedEnvKeysEnv bookkeeping entry.
func TestIncubatorEnvNoReplace(t *testing.T) {
	ss := newTestSession(t,
		[]string{"*"},
		[]string{
			"PATH=/client/evil",
			"HOME=/tmp/evil",
			"USER=root",
			"SHELL=/bin/evil",
			"SSH_CLIENT=198.51.100.9 1 2",
			"GIT_TOKEN=fromclient",
		},
	)
	_, forwardedEnv, err := ss.newIncubatorCommand(logger.Discard)
	if err != nil {
		t.Fatalf("newIncubatorCommand: %v", err)
	}
	env := ss.incubatorEnv(forwardedEnv)

	// Each server-set key appears exactly once, with the server's value
	for _, key := range []string{"PATH", "HOME", "USER", "SHELL", "SSH_CLIENT", "SSH_CONNECTION"} {
		var vals []string
		for _, kv := range env {
			if k, v, ok := strings.Cut(kv, "="); ok && k == key {
				vals = append(vals, v)
			}
		}
		if len(vals) != 1 {
			t.Errorf("%s appears %d times in env (values %q); want exactly one server-set value", key, len(vals), vals)
			continue
		}
		if strings.Contains(vals[0], "evil") || vals[0] == "root" || strings.HasPrefix(vals[0], "198.51.100.9") {
			t.Errorf("%s overridden by client value %q", key, vals[0])
		}
	}

	// Non-colliding forwarded vars are still delivered, and only delivered
	// names appear in the bookkeeping entry.
	if !slices.Contains(env, "GIT_TOKEN=fromclient") {
		t.Errorf("non-colliding forwarded var missing from env: %q", env)
	}
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == allowedEnvKeysEnv && v != "GIT_TOKEN" {
			t.Errorf("%s=%q, want only GIT_TOKEN (dropped collisions must not be named)", allowedEnvKeysEnv, v)
		}
	}
}

// TestForwardedEnvironAllowedKeys verifies that the incubator reconstructs the
// su -w allowlist from the (non-secret) key names carried in the allowedEnvKeysEnv
// environment variable, always including SSH_AUTH_SOCK, strips that bookkeeping
// variable from the environment handed to the user's process, and never depends
// on anything being present on the command line.
func TestForwardedEnvironAllowedKeys(t *testing.T) {
	tests := []struct {
		name        string
		allowedKeys string // value of allowedEnvKeysEnv, or "" to leave it unset
		wantKeys    []string
	}{
		{
			name:        "unset",
			allowedKeys: "",
			wantKeys:    []string{"SSH_AUTH_SOCK"},
		},
		{
			name:        "some_keys",
			allowedKeys: "GIT_ENV_VAR,EXACT_MATCH",
			wantKeys:    []string{"SSH_AUTH_SOCK", "GIT_ENV_VAR", "EXACT_MATCH"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.allowedKeys != "" {
				t.Setenv(allowedEnvKeysEnv, tc.allowedKeys)
			}
			gotEnv, gotKeys, err := incubatorArgs{}.forwardedEnviron()
			if err != nil {
				t.Fatalf("forwardedEnviron: %v", err)
			}
			if !slices.Equal(gotKeys, tc.wantKeys) {
				t.Errorf("allowedExtraKeys = %q, want %q", gotKeys, tc.wantKeys)
			}
			// The bookkeeping variable must never leak into the child's env.
			for _, kv := range gotEnv {
				if strings.HasPrefix(kv, allowedEnvKeysEnv+"=") {
					t.Errorf("%s leaked into child environment: %q", allowedEnvKeysEnv, kv)
				}
			}
		})
	}
}
