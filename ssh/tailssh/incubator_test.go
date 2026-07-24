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
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"
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

// newIncubatorCommandForTest calls newIncubatorCommand and arranges for the
// forwarded environment pipe to be closed at the end of the test.
func newIncubatorCommandForTest(t *testing.T, ss *sshSession) (*os.File, *exec.Cmd) {
	t.Helper()
	cmd, envFile, err := ss.newIncubatorCommand(logger.Discard)
	if err != nil {
		t.Fatalf("newIncubatorCommand: %v", err)
	}
	if envFile != nil {
		t.Cleanup(func() { envFile.Close() })
	}
	return envFile, cmd
}

var envFDFlag = "--env-fd=" + strconv.Itoa(incubatorEnvFD)

// TestForwardedEnvSecretNotOnArgvOrEnv is the core security regression test for
// the acceptEnv secret leak. A forwarded value must reach the incubator, but it
// must appear neither on the command line (cmd.Args, which is logged at session
// start and world-readable in /proc/<pid>/cmdline) nor in the incubator's own
// environment (cmd.Env, which belongs to a process that is still root and is
// inherited by su, login and the PAM stack). Only the descriptor number is on
// the argv.
func TestForwardedEnvSecretNotOnArgvOrEnv(t *testing.T) {
	const secret = "s3cr3t-token-value"
	ss := newTestSession(t,
		[]string{"GITLAB_API_TOKEN"},
		[]string{"GITLAB_API_TOKEN=" + secret, "IGNORED=nope"},
	)

	envFile, cmd := newIncubatorCommandForTest(t, ss)

	// Neither the secret value nor the key name may appear anywhere on the argv.
	argv := strings.Join(cmd.Args, "\x00")
	if strings.Contains(argv, secret) {
		t.Errorf("secret value leaked onto cmd.Args: %q", cmd.Args)
	}
	if strings.Contains(argv, "GITLAB_API_TOKEN") {
		t.Errorf("forwarded key name leaked onto cmd.Args: %q", cmd.Args)
	}
	// Only the file descriptor number does.
	if !slices.Contains(cmd.Args, envFDFlag) {
		t.Errorf("cmd.Args = %q, want it to contain %q", cmd.Args, envFDFlag)
	}

	// Nor may they appear in the still-privileged child's own environment.
	cmd.Env = ss.incubatorEnv()
	for _, kv := range cmd.Env {
		if strings.Contains(kv, secret) || strings.HasPrefix(kv, "GITLAB_API_TOKEN=") {
			t.Errorf("forwarded variable leaked into the incubator environment: %q", kv)
		}
	}

	// They travel over the pipe, which is handed to the child as fd 3.
	if envFile == nil {
		t.Fatal("newIncubatorCommand returned no environment file")
	}
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != envFile {
		t.Fatalf("cmd.ExtraFiles = %v, want exactly the environment file", cmd.ExtraFiles)
	}
	got, err := receiveForwardedEnv(envFile)
	if err != nil {
		t.Fatalf("receiveForwardedEnv: %v", err)
	}
	if want := []string{"GITLAB_API_TOKEN=" + secret}; !slices.Equal(got, want) {
		t.Errorf("payload = %q, want %q", got, want)
	}
}

// TestNoForwardedEnvNoFD verifies that the descriptor and its flag only appear
// when there is something to forward. (newIncubatorCommand itself panics if the
// two ever disagree.)
func TestNoForwardedEnvNoFD(t *testing.T) {
	for _, tc := range []struct {
		name      string
		acceptEnv []string
		environ   []string
	}{
		{"no-policy", nil, []string{"GIT_TOKEN=secret"}},
		{"nothing-matches", []string{"GIT_*"}, []string{"OTHER=1"}},
		{"nothing-sent", []string{"*"}, nil},
		{"everything-filtered", []string{"*"}, []string{"LD_PRELOAD=/tmp/evil.so"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss := newTestSession(t, tc.acceptEnv, tc.environ)
			envFile, cmd := newIncubatorCommandForTest(t, ss)
			if envFile != nil {
				t.Errorf("got an environment file, want none")
			}
			if len(cmd.ExtraFiles) != 0 {
				t.Errorf("cmd.ExtraFiles = %v, want none", cmd.ExtraFiles)
			}
			if slices.Contains(cmd.Args, envFDFlag) {
				t.Errorf("cmd.Args = %q, want no %s", cmd.Args, envFDFlag)
			}
		})
	}
}

// TestForwardedEnvPolicyTravelsWithPayload checks that the acceptEnv policy is
// sent alongside the accepted pairs, so the incubator can re-check them itself
// rather than trusting the parent.
func TestForwardedEnvPolicyTravelsWithPayload(t *testing.T) {
	acceptEnv := []string{"GIT_*", "EXACT_MATCH"}
	ss := newTestSession(t, acceptEnv, []string{"GIT_TOKEN=x", "NOPE=y"})
	envFile, _ := newIncubatorCommandForTest(t, ss)
	if envFile == nil {
		t.Fatal("newIncubatorCommand returned no environment file")
	}

	var p forwardedEnvPayload
	if err := json.NewDecoder(envFile).Decode(&p); err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	if !slices.Equal(p.AcceptEnv, acceptEnv) {
		t.Errorf("payload acceptEnv = %q, want %q", p.AcceptEnv, acceptEnv)
	}
	if want := []string{"GIT_TOKEN=x"}; !slices.Equal(p.Env, want) {
		t.Errorf("payload env = %q, want %q", p.Env, want)
	}
}

// TestIncubatorEnvContents pins what the incubator child's own environment may
// contain: server-derived values and the client's TERM/LANG/LC_*, and nothing
// else the client supplied.
func TestIncubatorEnvContents(t *testing.T) {
	ss := newTestSession(t,
		[]string{"*"},
		[]string{
			"TERM=xterm",
			"LANG=en_US.UTF-8",
			"LC_ALL=C",
			"PATH=/client/evil",
			"HOME=/tmp/evil",
			"GIT_TOKEN=secret",
			"LD_PRELOAD=/tmp/evil.so",
		},
	)
	env := ss.incubatorEnv()

	want := map[string]string{
		"SHELL":          "",
		"USER":           "alice",
		"HOME":           "/home/alice",
		"PATH":           "",
		"TERM":           "xterm",
		"LANG":           "en_US.UTF-8",
		"LC_ALL":         "C",
		"SSH_CLIENT":     "100.100.100.101 2222 22",
		"SSH_CONNECTION": "100.100.100.101 2222 100.100.100.102 22",
	}
	got := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("malformed entry %q", kv)
		}
		if _, dup := got[k]; dup {
			t.Errorf("duplicate key %q in incubator env %q", k, env)
		}
		got[k] = v
	}
	for k, v := range want {
		gotV, ok := got[k]
		if !ok {
			t.Errorf("incubator env missing %q; got %q", k, env)
			continue
		}
		if v != "" && gotV != v {
			t.Errorf("%s = %q, want %q", k, gotV, v)
		}
		delete(got, k)
	}
	if len(got) > 0 {
		t.Errorf("unexpected keys in incubator env: %v", got)
	}
	if got := len(env); got != len(want) {
		t.Errorf("incubator env has %d entries, want %d: %q", got, len(want), env)
	}
}

// writeEnvFD writes payload to a pipe and returns the read end's descriptor
// number, as the incubator child would receive it. The descriptor is owned by
// the caller of loadForwardedEnv, which closes it.
func writeEnvFD(t *testing.T, payload []byte) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer w.Close()
		w.Write(payload)
	}()
	// Dup so that closing our os.File does not close the descriptor the code
	// under test is given (and vice versa).
	fd, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	return fd
}

// fdOpen reports whether fd is still open in this process.
func fdOpen(fd int) bool {
	var stat syscall.Stat_t
	return syscall.Fstat(fd, &stat) == nil
}

// TestLoadForwardedEnvFromFD exercises the child side end to end: parse the
// argv the parent produced, read the descriptor, and hand the result to the
// user's environment and to the "su -w" allowlist.
func TestLoadForwardedEnvFromFD(t *testing.T) {
	payload, err := json.Marshal(forwardedEnvPayload{
		AcceptEnv: []string{"GIT_*", "EXACT_MATCH"},
		Env:       []string{"GIT_TOKEN=s3cr3t", "EXACT_MATCH=yes"},
	})
	if err != nil {
		t.Fatal(err)
	}
	fd := writeEnvFD(t, payload)

	ia, err := parseIncubatorArgs([]string{
		"--groups=1000",
		"--local-user=alice",
		"--env-fd=" + strconv.Itoa(fd),
	})
	if err != nil {
		t.Fatalf("parseIncubatorArgs: %v", err)
	}
	if ia.envFD != fd {
		t.Fatalf("envFD = %d, want %d", ia.envFD, fd)
	}
	if err := ia.loadForwardedEnv(); err != nil {
		t.Fatalf("loadForwardedEnv: %v", err)
	}
	want := []string{"GIT_TOKEN=s3cr3t", "EXACT_MATCH=yes"}
	if !slices.Equal(ia.forwardedEnv, want) {
		t.Errorf("forwardedEnv = %q, want %q", ia.forwardedEnv, want)
	}

	// The descriptor must not be left open to be inherited by the user's
	// process.
	if fdOpen(fd) {
		t.Errorf("fd %d still open after loadForwardedEnv", fd)
	}

	// The forwarded variables reach the user's environment, and their names
	// reach the "su -w" allowlist.
	env, keys := ia.forwardedEnviron()
	for _, kv := range want {
		if !slices.Contains(env, kv) {
			t.Errorf("env missing %q", kv)
		}
	}
	if wantKeys := []string{"SSH_AUTH_SOCK", "GIT_TOKEN", "EXACT_MATCH"}; !slices.Equal(keys, wantKeys) {
		t.Errorf("allowlist = %q, want %q", keys, wantKeys)
	}
}

// TestLoadForwardedEnvRejectsBadPayload checks that the incubator fails the
// session rather than continuing with an environment it could not validate.
func TestLoadForwardedEnvRejectsBadPayload(t *testing.T) {
	fd := writeEnvFD(t, []byte("not json"))
	ia := incubatorArgs{envFD: fd}
	if err := ia.loadForwardedEnv(); err == nil {
		t.Fatal("got nil error, want failure")
	}
	if fdOpen(fd) {
		t.Errorf("fd %d still open after loadForwardedEnv", fd)
	}
}

// TestLoadForwardedEnvRejectsBadFD checks that a descriptor number that could
// never have come from ExtraFiles is rejected rather than read: fds 0, 1 and 2
// are the session's stdio.
func TestLoadForwardedEnvRejectsBadFD(t *testing.T) {
	for _, fd := range []int{1, 2, -1} {
		ia := incubatorArgs{envFD: fd}
		if err := ia.loadForwardedEnv(); err == nil {
			t.Errorf("--env-fd=%d: got nil error, want failure", fd)
		}
	}
}

// TestLoadForwardedEnvEnforcesPolicy is the child-side trust boundary: even
// though the parent already filtered, the incubator re-applies the policy from
// the payload, so a parent bug cannot widen what is forwarded.
func TestLoadForwardedEnvEnforcesPolicy(t *testing.T) {
	payload, err := json.Marshal(forwardedEnvPayload{
		AcceptEnv: []string{"GIT_*"},
		Env: []string{
			"GIT_TOKEN=ok",
			"NOT_IN_POLICY=nope",       // parent should never have sent this
			"LD_PRELOAD=/tmp/evil.so",  // nor this
			"GIT_INJECT,EXTRA=nor+his", // nor a name that breaks "su -w"
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ia := incubatorArgs{envFD: writeEnvFD(t, payload)}
	if err := ia.loadForwardedEnv(); err != nil {
		t.Fatalf("loadForwardedEnv: %v", err)
	}
	if want := []string{"GIT_TOKEN=ok"}; !slices.Equal(ia.forwardedEnv, want) {
		t.Errorf("forwardedEnv = %q, want %q", ia.forwardedEnv, want)
	}
	_, keys := ia.forwardedEnviron()
	for _, bad := range []string{"NOT_IN_POLICY", "LD_PRELOAD", "GIT_INJECT", "EXTRA"} {
		if slices.Contains(keys, bad) {
			t.Errorf("%q reached the su -w allowlist %q", bad, keys)
		}
	}
}

// TestLoadForwardedEnvLegacyEncodedEnv covers the deprecated --encoded-env
// path, which is retained only so that this binary keeps working when it is
// exec'd by an outdated parent tailscaled.
func TestLoadForwardedEnvLegacyEncodedEnv(t *testing.T) {
	ia, err := parseIncubatorArgs([]string{
		"--groups=1000",
		fmt.Sprintf("--encoded-env=%q", `["GIT_ENV_VAR=working1","LD_PRELOAD=/tmp/evil.so"]`),
	})
	if err != nil {
		t.Fatalf("parseIncubatorArgs: %v", err)
	}
	if err := ia.loadForwardedEnv(); err != nil {
		t.Fatalf("loadForwardedEnv: %v", err)
	}
	// The policy is unavailable on this path, but the unconditional rules
	// still apply.
	if want := []string{"GIT_ENV_VAR=working1"}; !slices.Equal(ia.forwardedEnv, want) {
		t.Errorf("forwardedEnv = %q, want %q", ia.forwardedEnv, want)
	}
	env, keys := ia.forwardedEnviron()
	if !slices.Contains(env, "GIT_ENV_VAR=working1") {
		t.Errorf("env missing the legacy variable: %q", env)
	}
	if wantKeys := []string{"SSH_AUTH_SOCK", "GIT_ENV_VAR"}; !slices.Equal(keys, wantKeys) {
		t.Errorf("allowlist = %q, want %q", keys, wantKeys)
	}
}

// TestLoadForwardedEnvBothSources covers the (transient, unexpected) case of a
// parent that passes both channels: everything is merged, and each name still
// appears only once in the allowlist.
func TestLoadForwardedEnvBothSources(t *testing.T) {
	payload, err := json.Marshal(forwardedEnvPayload{
		AcceptEnv: []string{"*"},
		Env:       []string{"FROM_FD=1", "DUPLICATE=fd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ia := incubatorArgs{
		envFD:      writeEnvFD(t, payload),
		encodedEnv: fmt.Sprintf("%q", `["FROM_FLAG=2","DUPLICATE=flag"]`),
	}
	if err := ia.loadForwardedEnv(); err != nil {
		t.Fatalf("loadForwardedEnv: %v", err)
	}
	_, keys := ia.forwardedEnviron()
	if wantKeys := []string{"SSH_AUTH_SOCK", "FROM_FD", "DUPLICATE", "FROM_FLAG"}; !slices.Equal(keys, wantKeys) {
		t.Errorf("allowlist = %q, want %q", keys, wantKeys)
	}
}

// TestForwardedEnvironNoReplace pins the collision rule where it is enforced,
// in the child: a forwarded variable never replaces a value the parent set in
// the incubator's environment, and dropped names stay out of the "su -w"
// allowlist.
func TestForwardedEnvironNoReplace(t *testing.T) {
	t.Setenv("PATH", "/server/bin")
	t.Setenv("HOME", "/home/alice")
	t.Setenv("SSH_AUTH_SOCK", "/server/sock")

	ia := incubatorArgs{forwardedEnv: []string{
		"PATH=/client/evil",
		"HOME=/tmp/evil",
		"SSH_AUTH_SOCK=/client/sock",
		"GIT_TOKEN=fromclient",
	}}
	env, keys := ia.forwardedEnviron()

	for _, kv := range []string{"PATH=/server/bin", "HOME=/home/alice", "SSH_AUTH_SOCK=/server/sock"} {
		if !slices.Contains(env, kv) {
			t.Errorf("env missing server value %q", kv)
		}
		k, _, _ := strings.Cut(kv, "=")
		var n int
		for _, e := range env {
			if ek, _, _ := strings.Cut(e, "="); ek == k {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s appears %d times in env, want once", k, n)
		}
	}
	for _, kv := range env {
		if strings.Contains(kv, "evil") || kv == "SSH_AUTH_SOCK=/client/sock" {
			t.Errorf("client value survived: %q", kv)
		}
	}
	if !slices.Contains(env, "GIT_TOKEN=fromclient") {
		t.Errorf("non-colliding forwarded var missing from env")
	}
	if want := []string{"SSH_AUTH_SOCK", "GIT_TOKEN"}; !slices.Equal(keys, want) {
		t.Errorf("allowlist = %q, want %q", keys, want)
	}
}

// TestForwardedEnvironNothingForwarded verifies the common case: no forwarded
// variables means the environment is untouched and the allowlist holds only
// SSH_AUTH_SOCK, which is allowlisted unconditionally because an agent socket,
// if any, is placed in the environment by the parent.
func TestForwardedEnvironNothingForwarded(t *testing.T) {
	env, keys := incubatorArgs{}.forwardedEnviron()
	if !slices.Equal(env, os.Environ()) {
		t.Errorf("env = %q, want the process environment unchanged", env)
	}
	if want := []string{"SSH_AUTH_SOCK"}; !slices.Equal(keys, want) {
		t.Errorf("allowlist = %q, want %q", keys, want)
	}
}

// TestForwardedEnvFDCrossProcess exercises the transport across a real process
// boundary, which is the one thing the in-process tests cannot check: that
// exec.Cmd.ExtraFiles[0] really does arrive as incubatorEnvFD in the child, and
// that a child parsing the argv the parent produced can read the payload from
// it.
//
// The test re-executes the test binary as the child; the child branch below
// runs the same parse-then-load sequence beIncubator does.
func TestForwardedEnvFDCrossProcess(t *testing.T) {
	const (
		childEnv     = "TS_TEST_INCUBATOR_ENV_CHILD"
		childArgsEnv = "TS_TEST_INCUBATOR_ENV_ARGS"
		resultPrefix = "FORWARDED_ENV_RESULT:"
	)

	if os.Getenv(childEnv) == "1" {
		report := func(format string, args ...any) {
			fmt.Printf(resultPrefix+format+"\n", args...)
		}
		ia, err := parseIncubatorArgs(strings.Fields(os.Getenv(childArgsEnv)))
		if err != nil {
			report("parse error: %v", err)
			return
		}
		if err := ia.loadForwardedEnv(); err != nil {
			report("load error: %v", err)
			return
		}
		b, err := json.Marshal(ia.forwardedEnv)
		if err != nil {
			report("marshal error: %v", err)
			return
		}
		report("%s", b)
		return
	}

	f, err := forwardedEnvFile(logger.Discard, []string{"GIT_*"}, []string{"GIT_TOKEN=s3cr3t", "GIT_OTHER=two"})
	if err != nil {
		t.Fatalf("forwardedEnvFile: %v", err)
	}
	defer f.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestForwardedEnvFDCrossProcess$")
	cmd.Env = append(os.Environ(),
		childEnv+"=1",
		childArgsEnv+"=--groups=1000 --local-user=alice "+envFDFlag,
	)
	cmd.ExtraFiles = []*os.File{f}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}

	var result string
	for _, line := range strings.Split(string(out), "\n") {
		if s, ok := strings.CutPrefix(strings.TrimSpace(line), resultPrefix); ok {
			result = s
		}
	}
	if result == "" {
		t.Fatalf("no result from child; output:\n%s", out)
	}
	if want := `["GIT_TOKEN=s3cr3t","GIT_OTHER=two"]`; result != want {
		t.Errorf("child read %s, want %s", result, want)
	}
}

// TestLoadForwardedEnvLegacyCollisionsDropped documents a deliberate behavior
// change on the version-skew path. An outdated parent's --encoded-env pairs
// used to be appended to the environment unconditionally, so a forwarded PATH
// overrode the server's. They now go through mergeForwardedEnv like everything
// else and lose the collision.
func TestLoadForwardedEnvLegacyCollisionsDropped(t *testing.T) {
	t.Setenv("PATH", "/server/bin")

	ia := incubatorArgs{encodedEnv: fmt.Sprintf("%q", `["PATH=/client/evil","OK=1"]`)}
	if err := ia.loadForwardedEnv(); err != nil {
		t.Fatalf("loadForwardedEnv: %v", err)
	}
	env, keys := ia.forwardedEnviron()

	if !slices.Contains(env, "PATH=/server/bin") {
		t.Errorf("server PATH missing from env")
	}
	if slices.Contains(env, "PATH=/client/evil") {
		t.Errorf("client PATH survived: %q", env)
	}
	if slices.Contains(keys, "PATH") {
		t.Errorf("PATH must not reach the su -w allowlist: %q", keys)
	}
	if !slices.Contains(env, "OK=1") {
		t.Errorf("non-colliding legacy var missing from env")
	}
}
