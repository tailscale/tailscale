// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package envknob provides access to environment-variable tweakable
// debug settings.
//
// These are primarily knobs used by Tailscale developers during
// development or by users when instructed to by Tailscale developers
// when debugging something. They are not a stable interface and may
// be removed or any time.
//
// A related package, control/controlknobs, are knobs that can be
// changed at runtime by the control plane. Sometimes both are used:
// an envknob for the default/explicit value, else falling back
// to the controlknob value.
package envknob

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"tailscale.com/types/opt"
	"tailscale.com/version/distro"
)

var (
	mu         sync.Mutex
	set        = map[string]string{}
	regStr     = map[string]*string{}
	regBool    = map[string]*bool{}
	regOptBool = map[string]*opt.Bool{}
)

func noteEnv(k, v string) {
	mu.Lock()
	defer mu.Unlock()
	noteEnvLocked(k, v)
}

func noteEnvLocked(k, v string) {
	if v != "" {
		set[k] = v
	} else {
		delete(set, k)
	}
}

// logf is logger.Logf, but logger depends on envknob, so for circular
// dependency reasons, make a type alias (so it's still assignable,
// but has nice docs here).
type logf = func(format string, args ...any)

// LogCurrent logs the currently set environment knobs.
func LogCurrent(logf logf) {
	mu.Lock()
	defer mu.Unlock()

	list := make([]string, 0, len(set))
	for k := range set {
		list = append(list, k)
	}
	sort.Strings(list)
	for _, k := range list {
		logf("envknob: %s=%q", k, set[k])
	}
}

// Setenv changes an environment variable.
//
// It is not safe for concurrent reading of environment variables via the
// Register functions. All Setenv calls are meant to happen early in main before
// any goroutines are started.
func Setenv(envVar, val string) {
	mu.Lock()
	defer mu.Unlock()
	os.Setenv(envVar, val)
	noteEnvLocked(envVar, val)

	if p := regStr[envVar]; p != nil {
		*p = val
	}
	if p := regBool[envVar]; p != nil {
		setBoolLocked(p, envVar, val)
	}
	if p := regOptBool[envVar]; p != nil {
		setOptBoolLocked(p, envVar, val)
	}
}

// String returns the named environment variable, using os.Getenv.
//
// If the variable is non-empty, it's also tracked & logged as being
// an in-use knob.
func String(envVar string) string {
	v := os.Getenv(envVar)
	noteEnv(envVar, v)
	return v
}

// RegisterString returns a func that gets the named environment variable,
// without a map lookup per call. It assumes that mutations happen via
// envknob.Setenv.
func RegisterString(envVar string) func() string {
	mu.Lock()
	defer mu.Unlock()
	p, ok := regStr[envVar]
	if !ok {
		val := os.Getenv(envVar)
		if val != "" {
			noteEnvLocked(envVar, val)
		}
		p = &val
		regStr[envVar] = p
	}
	return func() string { return *p }
}

// RegisterBool returns a func that gets the named environment variable,
// without a map lookup per call. It assumes that mutations happen via
// envknob.Setenv.
func RegisterBool(envVar string) func() bool {
	mu.Lock()
	defer mu.Unlock()
	p, ok := regBool[envVar]
	if !ok {
		var b bool
		p = &b
		setBoolLocked(p, envVar, os.Getenv(envVar))
		regBool[envVar] = p
	}
	return func() bool { return *p }
}

// RegisterOptBool returns a func that gets the named environment variable,
// without a map lookup per call. It assumes that mutations happen via
// envknob.Setenv.
func RegisterOptBool(envVar string) func() opt.Bool {
	mu.Lock()
	defer mu.Unlock()
	p, ok := regOptBool[envVar]
	if !ok {
		var b opt.Bool
		p = &b
		setOptBoolLocked(p, envVar, os.Getenv(envVar))
		regOptBool[envVar] = p
	}
	return func() opt.Bool { return *p }
}

func setBoolLocked(p *bool, envVar, val string) {
	noteEnvLocked(envVar, val)
	if val == "" {
		*p = false
		return
	}
	var err error
	*p, err = strconv.ParseBool(val)
	if err != nil {
		log.Fatalf("invalid boolean environment variable %s value %q", envVar, val)
	}
}

func setOptBoolLocked(p *opt.Bool, envVar, val string) {
	noteEnvLocked(envVar, val)
	if val == "" {
		*p = ""
		return
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		log.Fatalf("invalid boolean environment variable %s value %q", envVar, val)
	}
	p.Set(b)
}

// Bool returns the boolean value of the named environment variable.
// If the variable is not set, it returns false.
// An invalid value exits the binary with a failure.
func Bool(envVar string) bool {
	return boolOr(envVar, false)
}

// BoolDefaultTrue is like Bool, but returns true by default if the
// environment variable isn't present.
func BoolDefaultTrue(envVar string) bool {
	return boolOr(envVar, true)
}

func boolOr(envVar string, implicitValue bool) bool {
	assertNotInInit()
	val := os.Getenv(envVar)
	if val == "" {
		return implicitValue
	}
	b, err := strconv.ParseBool(val)
	if err == nil {
		noteEnv(envVar, strconv.FormatBool(b)) // canonicalize
		return b
	}
	log.Fatalf("invalid boolean environment variable %s value %q", envVar, val)
	panic("unreachable")
}

// LookupBool returns the boolean value of the named environment value.
// The ok result is whether a value was set.
// If the value isn't a valid int, it exits the program with a failure.
func LookupBool(envVar string) (v bool, ok bool) {
	assertNotInInit()
	val := os.Getenv(envVar)
	if val == "" {
		return false, false
	}
	b, err := strconv.ParseBool(val)
	if err == nil {
		return b, true
	}
	log.Fatalf("invalid boolean environment variable %s value %q", envVar, val)
	panic("unreachable")
}

// OptBool is like Bool, but returns an opt.Bool, so the caller can
// distinguish between implicitly and explicitly false.
func OptBool(envVar string) opt.Bool {
	assertNotInInit()
	b, ok := LookupBool(envVar)
	if !ok {
		return ""
	}
	var ret opt.Bool
	ret.Set(b)
	return ret
}

// LookupInt returns the integer value of the named environment value.
// The ok result is whether a value was set.
// If the value isn't a valid int, it exits the program with a failure.
func LookupInt(envVar string) (v int, ok bool) {
	assertNotInInit()
	val := os.Getenv(envVar)
	if val == "" {
		return 0, false
	}
	v, err := strconv.Atoi(val)
	if err == nil {
		noteEnv(envVar, val)
		return v, true
	}
	log.Fatalf("invalid integer environment variable %s: %v", envVar, val)
	panic("unreachable")
}

// UseWIPCode is whether TAILSCALE_USE_WIP_CODE is set to permit use
// of Work-In-Progress code.
func UseWIPCode() bool { return Bool("TAILSCALE_USE_WIP_CODE") }

// CanSSHD is whether the Tailscale SSH server is allowed to run.
//
// If disabled, the SSH server won't start (won't intercept port 22)
// if already enabled and any attempt to re-enable it will result in
// an error.
func CanSSHD() bool { return !Bool("TS_DISABLE_SSH_SERVER") }

// SSHPolicyFile returns the path, if any, to the SSHPolicy JSON file for development.
func SSHPolicyFile() string { return String("TS_DEBUG_SSH_POLICY_FILE") }

// SSHIgnoreTailnetPolicy is whether to ignore the Tailnet SSH policy for development.
func SSHIgnoreTailnetPolicy() bool { return Bool("TS_DEBUG_SSH_IGNORE_TAILNET_POLICY") }


// TKASkipSignatureCheck is whether to skip node-key signature checking for development.
func TKASkipSignatureCheck() bool { return Bool("TS_UNSAFE_SKIP_NKS_VERIFICATION") }


// NoLogsNoSupport reports whether the client's opted out of log uploads and
// technical support.
func NoLogsNoSupport() bool {
	return Bool("TS_NO_LOGS_NO_SUPPORT")
}

// SetNoLogsNoSupport enables no-logs-no-support mode.
func SetNoLogsNoSupport() {
	Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
}

// notInInit is set true the first time we've seen a non-init stack trace.
var notInInit atomic.Bool

func assertNotInInit() {
	if notInInit.Load() {
		return
	}
	skip := 0
	for {
		pc, _, _, ok := runtime.Caller(skip)
		if !ok {
			notInInit.Store(true)
			return
		}
		fu := runtime.FuncForPC(pc)
		if fu == nil {
			return
		}
		name := fu.Name()
		name = strings.TrimRightFunc(name, func(r rune) bool { return r >= '0' && r <= '9' })
		if strings.HasSuffix(name, ".init") || strings.HasSuffix(name, ".init.") {
			stack := make([]byte, 1<<10)
			stack = stack[:runtime.Stack(stack, false)]
			envCheckedInInitStack = stack
		}
		skip++
	}
}

var envCheckedInInitStack []byte

// PanicIfAnyEnvCheckedInInit panics if environment variables were read during
// init.
func PanicIfAnyEnvCheckedInInit() {
	if envCheckedInInitStack != nil {
		panic("envknob check of called from init function: " + string(envCheckedInInitStack))
	}
}

var applyDiskConfigErr error

// ApplyDiskConfigError returns the most recent result of ApplyDiskConfig.
func ApplyDiskConfigError() error { return applyDiskConfigErr }

// ApplyDiskConfig returns a platform-specific config file of environment keys/values and
// applies them. On Linux and Unix operating systems, it's a no-op and always returns nil.
// If no platform-specific config file is found, it also returns nil.
//
// It exists primarily for Windows to make it easy to apply environment variables to
// a running service in a way similar to modifying /etc/default/tailscaled on Linux.
// On Windows, you use %ProgramData%\Tailscale\tailscaled-env.txt instead.
func ApplyDiskConfig() (err error) {
	var f *os.File
	defer func() {
		if err != nil {
			// Stash away our return error for the healthcheck package to use.
			applyDiskConfigErr = fmt.Errorf("error parsing %s: %w", f.Name(), err)
		}
	}()

	// First try the explicitly-provided value for development testing. Not
	// useful for users to use on their own. (if they can set this, they can set
	// any environment variable anyway)
	if name := os.Getenv("TS_DEBUG_ENV_FILE"); name != "" {
		f, err = os.Open(name)
		if err != nil {
			return fmt.Errorf("error opening explicitly configured TS_DEBUG_ENV_FILE: %w", err)
		}
		defer f.Close()
		return applyKeyValueEnv(f)
	}

	name := getPlatformEnvFile()
	if name == "" {
		return nil
	}
	f, err = os.Open(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	return applyKeyValueEnv(f)
}

// getPlatformEnvFile returns the current platform's path to an optional
// tailscaled-env.txt file. It returns an empty string if none is defined
// for the platform.
func getPlatformEnvFile() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "Tailscale", "tailscaled-env.txt")
	case "linux":
		if distro.Get() == distro.Synology {
			return "/etc/tailscale/tailscaled-env.txt"
		}
	case "darwin":
		// TODO(bradfitz): figure this out. There are three ways to run
		// Tailscale on macOS (tailscaled, GUI App Store, GUI System Extension)
		// and we should deal with all three.
	}
	return ""
}

// applyKeyValueEnv reads key=value lines r and calls Setenv for each.
//
// Empty lines and lines beginning with '#' are skipped.
//
// Values can be double quoted, in which case they're unquoted using
// strconv.Unquote.
func applyKeyValueEnv(r io.Reader) error {
	bs := bufio.NewScanner(r)
	for bs.Scan() {
		line := strings.TrimSpace(bs.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, `"`) {
			var err error
			v, err = strconv.Unquote(v)
			if err != nil {
				return fmt.Errorf("invalid value in line %q: %v", line, err)
			}
		}
		Setenv(k, v)
	}
	return bs.Err()
}
