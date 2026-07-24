// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"tailscale.com/types/logger"
)

// isDangerousEnvVar reports whether the given environment variable name
// is unconditionally prohibited from being forwarded, regardless of
// acceptEnv policy. This prevents privilege escalation via dynamic
// linker environment variables (e.g. LD_PRELOAD, LD_LIBRARY_PATH,
// DYLD_INSERT_LIBRARIES) or leaking of secrets (e.g. GOTRACEBACK)
// even when a wildcard acceptEnv pattern like "*" is configured.
//
// The client-forwarded variables no longer land in the incubator's own
// environment (they travel over a pipe, see forwardedEnvPayload), but their
// names are still handed to "su -w", which re-materializes them in the
// environment of su itself while it is still root, so this check remains
// load-bearing.
func isDangerousEnvVar(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") ||
		upper == "GOTRACEBACK"
}

// validEnvName reports whether name is structurally usable as the name of a
// client-forwarded environment variable, independent of the acceptEnv policy.
//
// Names must be non-empty and must not contain:
//   - "=", which would make the "KEY=VALUE" encoding ambiguous;
//   - ",", which separates the names in the "su -w" allowlist the incubator
//     builds from them, so a comma would let a client inject additional
//     entries into that allowlist;
//   - whitespace or non-printable characters, which no legitimate variable
//     name contains and which would make the allowlist, the environment and
//     any logs of them ambiguous.
func validEnvName(name string) bool {
	if name == "" || strings.ContainsAny(name, "=,") {
		return false
	}
	for _, r := range name {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

const (
	// incubatorEnvFD is the file descriptor at which the incubator child finds
	// the pipe carrying the client-forwarded environment. os/exec maps the
	// first entry of exec.Cmd.ExtraFiles to fd 3 in the child, and the
	// incubator is never passed any other extra files.
	incubatorEnvFD = 3

	// maxForwardedEnvEntry bounds a single forwarded "KEY=VALUE" pair.
	//
	// This is not an arbitrary number: the environment we build is ultimately
	// handed to execve, and Linux rejects any single argument or environment
	// entry larger than MAX_ARG_STRLEN (32 pages, 131072 bytes) with E2BIG.
	// Accepting more here would only defer the failure to the exec of su or
	// login, which happens after the PAM session has been opened and reports
	// nothing more useful than E2BIG.
	maxForwardedEnvEntry = 128 << 10

	// maxForwardedEnvSize bounds the whole JSON forwardedEnvPayload, in both
	// directions, so that neither side can be made to buffer an unreasonable
	// amount of client-supplied data. Real environments are a few KB at most;
	// OpenSSH's own limit is 8KB per variable. It is also kept well under
	// ARG_MAX (typically 2MB, shared with the argv and the rest of the
	// environment) for the same reason as maxForwardedEnvEntry.
	maxForwardedEnvSize = 256 << 10

	// forwardedEnvPipeTimeout bounds how long the parent waits for the child
	// to drain the forwarded environment pipe. A child that never reads (an
	// old binary, or one that died early) must not leave the writing goroutine
	// and its file descriptor around forever.
	forwardedEnvPipeTimeout = 30 * time.Second
)

// forwardedEnvPayload is the JSON document the parent (tailscaled) writes to
// the incubator child over a dedicated pipe, and the only channel by which
// client-supplied environment variables reach the child.
//
// It is deliberately neither on the argv nor in the child's environment:
//
//   - The argv of the incubator is world-readable via /proc/<pid>/cmdline and
//     is logged at session start (locally, and to log.tailscale.com unless
//     --no-logs-no-support is set), so neither the values nor the names of the
//     forwarded variables can go there.
//   - The child's environment is the environment of a process that is still
//     root: the incubator itself, the PAM stack it runs, and the su or login
//     it execs all read it before privileges are dropped. Client-controlled
//     entries there are an injection surface, and /proc/<pid>/environ is
//     readable by the user we are about to become.
//
// The payload carries the acceptEnv policy alongside the accepted pairs so
// that the child can re-run the same filter itself rather than trusting that
// the parent filtered correctly. The privileged process enforces the name
// allowlist at the point of use.
type forwardedEnvPayload struct {
	// AcceptEnv is the acceptEnv policy from the matching SSH rule: the
	// (possibly wildcarded) variable names the policy allows to be forwarded.
	AcceptEnv []string `json:"acceptEnv,omitempty"`

	// Env is the "KEY=VALUE" pairs the client sent that the parent accepted
	// under AcceptEnv. The child re-checks them against AcceptEnv.
	Env []string `json:"env,omitempty"`
}

// forwardedEnvFile returns the read end of a pipe from which the incubator
// child can read the JSON encoding of a forwardedEnvPayload holding the given
// acceptEnv policy and accepted "KEY=VALUE" pairs. The caller passes it to the
// child as exec.Cmd.ExtraFiles[0], where it appears as fd incubatorEnvFD.
//
// The payload is written by a goroutine rather than inline because a pipe
// holds only ~64KB and the child does not read until it starts. The write is
// bounded by forwardedEnvPipeTimeout; if it does not complete the child sees a
// truncated payload and fails closed rather than starting a session with a
// half-populated environment.
//
// The caller owns the returned file and must close it once the child has been
// started (or has failed to start).
func forwardedEnvFile(logf logger.Logf, acceptEnv, env []string) (*os.File, error) {
	if err := checkForwardedEnvSizes(env); err != nil {
		return nil, err
	}
	b, err := json.Marshal(forwardedEnvPayload{AcceptEnv: acceptEnv, Env: env})
	if err != nil {
		return nil, fmt.Errorf("marshaling forwarded environment: %w", err)
	}
	if len(b) > maxForwardedEnvSize {
		return nil, fmt.Errorf("forwarded environment too large: %d bytes, max %d", len(b), maxForwardedEnvSize)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating forwarded environment pipe: %w", err)
	}
	if err := w.SetWriteDeadline(time.Now().Add(forwardedEnvPipeTimeout)); err != nil {
		// Not every platform supports deadlines on pipes. Without one, a child
		// that never reads leaves the goroutine below parked for the lifetime
		// of the process, so say so rather than failing silently.
		logf("tailssh: no write deadline on the forwarded environment pipe: %v", err)
	}
	go func() {
		defer w.Close()
		if _, err := w.Write(b); err != nil {
			// The child will see a short read and fail the session; without
			// this line there is nothing anywhere saying why.
			logf("tailssh: writing forwarded environment to child: %v", err)
		}
	}()
	return r, nil
}

// checkForwardedEnvSizes reports an error if any "KEY=VALUE" pair is too large
// for the execve that will eventually carry it. See maxForwardedEnvEntry.
//
// Error messages name only the key, and truncate even that: the value is
// secret, and a malformed pair with no "=" is entirely "key".
func checkForwardedEnvSizes(env []string) error {
	for _, kv := range env {
		if len(kv) <= maxForwardedEnvEntry {
			continue
		}
		k, _, _ := strings.Cut(kv, "=")
		if len(k) > 64 {
			k = k[:64] + "..."
		}
		return fmt.Errorf("forwarded environment variable %q is %d bytes, over the %d byte limit", k, len(kv), maxForwardedEnvEntry)
	}
	return nil
}

// receiveForwardedEnv reads a JSON forwardedEnvPayload from r and returns the
// client-forwarded "KEY=VALUE" pairs that survive filtering. Anything
// malformed fails the session rather than being silently ignored.
//
// The incubator re-applies the filter here, at the point of use, rather than
// relying on the parent having done it. Note what that is and is not worth:
//
//   - The unconditional rules (isDangerousEnvVar, validEnvName, the size
//     limits) are real invariants. They hold no matter what the parent sends,
//     and they are what stands between a wildcard acceptEnv policy and the
//     root su or login this environment is about to reach.
//   - Re-running the acceptEnv patterns is only a check against parent bugs.
//     The policy travels in the same payload as the data, so it is not a trust
//     boundary: a parent that mismatched patterns is caught, a parent that has
//     been subverted simply sends acceptEnv:["*"].
func receiveForwardedEnv(r io.Reader) ([]string, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxForwardedEnvSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading forwarded environment: %w", err)
	}
	if len(b) > maxForwardedEnvSize {
		return nil, fmt.Errorf("forwarded environment too large: max %d bytes", maxForwardedEnvSize)
	}
	var p forwardedEnvPayload
	if err := json.Unmarshal(b, &p); err != nil {
		// Call out the short-read case: a truncated write by the parent (see
		// forwardedEnvFile) surfaces here as invalid JSON, and the byte count
		// is the only thing distinguishing it from a corrupt payload.
		return nil, fmt.Errorf("parsing forwarded environment (%d bytes read; a short read means the parent's write was truncated): %w", len(b), err)
	}
	if err := checkForwardedEnvSizes(p.Env); err != nil {
		return nil, err
	}
	env, err := filterEnv(p.AcceptEnv, p.Env)
	if err != nil {
		return nil, fmt.Errorf("filtering forwarded environment: %w", err)
	}
	return env, nil
}

// parseLegacyEncodedEnv parses the value of the deprecated --encoded-env flag:
// a quoted JSON array of "KEY=VALUE" strings.
//
// DEPRECATED: this exists only so that a new incubator keeps working when it is
// exec'd by an outdated parent tailscaled that still passes --encoded-env. New
// parents use forwardedEnvPayload. See beIncubator, which warns when this path
// is taken.
//
// The acceptEnv policy is not available on this path (an old parent does not
// send it), so only the policy-independent rules can be re-applied here. That
// is still worth doing: an old parent's copy of them may be missing entries
// that have since been added.
//
// Note one deliberate behavior change for old parents: these pairs used to be
// appended to the environment unconditionally, so a forwarded PATH or HOME
// would override the server's value. They now go through mergeForwardedEnv
// like everything else and lose such collisions.
func parseLegacyEncodedEnv(encoded string) ([]string, error) {
	unquoted, err := strconv.Unquote(encoded)
	if err != nil {
		return nil, fmt.Errorf("unable to parse encodedEnv %q: %w", encoded, err)
	}
	var env []string
	if err := json.Unmarshal([]byte(unquoted), &env); err != nil {
		return nil, fmt.Errorf("unable to parse encodedEnv %q: %w", encoded, err)
	}
	return filterUnsafeEnv(env), nil
}

// filterUnsafeEnv returns the "KEY=VALUE" pairs of environ that are well
// formed, validly named and not dangerous. It applies exactly the subset of
// filterEnv's checks that does not depend on an acceptEnv policy.
func filterUnsafeEnv(environ []string) []string {
	return slices.DeleteFunc(slices.Clone(environ), func(kv string) bool {
		k, _, ok := strings.Cut(kv, "=")
		return !ok || !validEnvName(k) || isDangerousEnvVar(k)
	})
}

// mergeForwardedEnv returns environ with the client-forwarded pairs appended,
// plus the names of the pairs that were actually appended, for the incubator's
// "su -w" allowlist.
//
// A forwarded pair is dropped if its name is already present in environ: the
// environment the parent built for the child holds server-derived values
// (PATH, HOME, SHELL, USER, SSH_AUTH_SOCK, SSH_CLIENT, ...) that the client
// must not be able to replace. Duplicate names within forwarded are dropped
// too, first one wins, so no name can appear twice in the allowlist.
//
// environ is appended to, so the caller must pass a slice it owns, such as a
// fresh os.Environ().
func mergeForwardedEnv(environ, forwarded []string) (env, keys []string) {
	seen := make(map[string]bool, len(environ))
	for _, kv := range environ {
		if k, _, ok := strings.Cut(kv, "="); ok {
			seen[k] = true
		}
	}
	env = environ
	for _, kv := range forwarded {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		env = append(env, kv)
		keys = append(keys, k)
	}
	return env, keys
}

// filterEnv filters a passed in environ string slice (a slice with strings
// representing environment variables in the form "key=value") based on
// the supplied slice of acceptEnv values.
//
// acceptEnv is a slice of environment variable names that are allowlisted
// for the SSH rule in the policy file.
//
// acceptEnv values may contain * and ? wildcard characters which match against
// zero or one or more characters and a single character respectively.
//
// Certain dangerous environment variables (such as those controlling the
// dynamic linker) are always rejected regardless of the acceptEnv policy,
// as are structurally unusable names. See isDangerousEnvVar and validEnvName.
//
// This runs in both the parent (to decide what to forward) and in the
// incubator child (to re-check what it was handed); see forwardedEnvPayload.
func filterEnv(acceptEnv []string, environ []string) ([]string, error) {
	var acceptedPairs []string

	// Quick return if we have an empty list.
	if acceptEnv == nil || len(acceptEnv) == 0 {
		return acceptedPairs, nil
	}

	for _, envPair := range environ {
		variableName, _, ok := strings.Cut(envPair, "=")
		if !ok {
			return nil, fmt.Errorf(`invalid environment variable: %q. Variables must be in "KEY=VALUE" format`, envPair)
		}

		// Always reject dangerous environment variables that could
		// enable privilege escalation, regardless of acceptEnv policy.
		if isDangerousEnvVar(variableName) {
			continue
		}

		// Always reject names that are empty or that carry characters which
		// would corrupt the incubator's "su -w" allowlist, regardless of
		// acceptEnv policy. See validEnvName.
		if !validEnvName(variableName) {
			continue
		}

		// Short circuit if we have a direct match between the environment
		// variable and an AcceptEnv value.
		if slices.Contains(acceptEnv, variableName) {
			acceptedPairs = append(acceptedPairs, envPair)
			continue
		}

		// Otherwise check if we have a wildcard pattern that matches.
		if matchAcceptEnv(acceptEnv, variableName) {
			acceptedPairs = append(acceptedPairs, envPair)
			continue
		}
	}

	return acceptedPairs, nil
}

// matchAcceptEnv is a convenience function that wraps calling matchAcceptEnvPattern
// with every value in acceptEnv for a given env that is being matched against.
func matchAcceptEnv(acceptEnv []string, env string) bool {
	for _, pattern := range acceptEnv {
		if matchAcceptEnvPattern(pattern, env) {
			return true
		}
	}

	return false
}

// matchAcceptEnvPattern returns true if the pattern matches against the target string.
// Patterns may include * and ? wildcard characters which match against zero or one or
// more characters and a single character respectively.
func matchAcceptEnvPattern(pattern string, target string) bool {
	patternIdx := 0
	targetIdx := 0

	for {
		// If we are at the end of the pattern we can only have a match if we
		// are also at the end of the target.
		if patternIdx >= len(pattern) {
			return targetIdx >= len(target)
		}

		if pattern[patternIdx] == '*' {
			// Optimization to skip through any repeated asterisks as they
			// have the same net effect on our search.
			for patternIdx < len(pattern) {
				if pattern[patternIdx] != '*' {
					break
				}

				patternIdx++
			}

			// We are at the end of the pattern after matching the asterisk,
			// implying a match.
			if patternIdx >= len(pattern) {
				return true
			}

			// Search through the target sequentially for the next character
			// from the pattern string, recursing into matchAcceptEnvPattern
			// to try and find a match.
			for ; targetIdx < len(target); targetIdx++ {
				if matchAcceptEnvPattern(pattern[patternIdx:], target[targetIdx:]) {
					return true
				}
			}

			// No match after searching through the entire target.
			return false
		}

		if targetIdx >= len(target) {
			return false
		}

		if pattern[patternIdx] != '?' && pattern[patternIdx] != target[targetIdx] {
			return false
		}

		patternIdx++
		targetIdx++
	}
}
