// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/opt"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

var (
	mu sync.Mutex
	// +checklocks:mu
	set = map[string]string{}
	// +checklocks:mu
	regStr = map[string]*string{}
	// +checklocks:mu
	regBool = map[string]*bool{}
	// +checklocks:mu
	regOptBool = map[string]*opt.Bool{}
	// +checklocks:mu
	regDuration = map[string]*time.Duration{}
	// +checklocks:mu
	regInt = map[string]*int{}
)

func noteEnv(k, v string) {
	mu.Lock()
	defer mu.Unlock()
	noteEnvLocked(k, v)
}

// +checklocks:mu
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

	for _, k := range slices.Sorted(maps.Keys(set)) {
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
	if p := regDuration[envVar]; p != nil {
		setDurationLocked(p, envVar, val)
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

// RegisterDuration returns a func that gets the named environment variable as a
// duration, without a map lookup per call. It assumes that any mutations happen
// via envknob.Setenv.
func RegisterDuration(envVar string) func() time.Duration {
	mu.Lock()
	defer mu.Unlock()
	p, ok := regDuration[envVar]
	if !ok {
		val := os.Getenv(envVar)
		if val != "" {
			noteEnvLocked(envVar, val)
		}
		p = new(time.Duration)
		setDurationLocked(p, envVar, val)
		regDuration[envVar] = p
	}
	return func() time.Duration { return *p }
}

// RegisterInt returns a func that gets the named environment variable as an
// integer, without a map lookup per call. It assumes that any mutations happen
// via envknob.Setenv.
func RegisterInt(envVar string) func() int {
	mu.Lock()
	defer mu.Unlock()
	p, ok := regInt[envVar]
	if !ok {
		val := os.Getenv(envVar)
		if val != "" {
			noteEnvLocked(envVar, val)
		}
		p = new(int)
		setIntLocked(p, envVar, val)
		regInt[envVar] = p
	}
	return func() int { return *p }
}

// +checklocks:mu
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

// +checklocks:mu
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

// +checklocks:mu
func setDurationLocked(p *time.Duration, envVar, val string) {
	noteEnvLocked(envVar, val)
	if val == "" {
		*p = 0
		return
	}
	var err error
	*p, err = time.ParseDuration(val)
	if err != nil {
		log.Fatalf("invalid duration environment variable %s value %q", envVar, val)
	}
}

// +checklocks:mu
func setIntLocked(p *int, envVar, val string) {
	noteEnvLocked(envVar, val)
	if val == "" {
		*p = 0
		return
	}
	var err error
	*p, err = strconv.Atoi(val)
	if err != nil {
		log.Fatalf("invalid int environment variable %s value %q", envVar, val)
	}
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

// LookupIntSized returns the integer value of the named environment value
// parsed in base and with a maximum bit size bitSize.
// The ok result is whether a value was set.
// If the value isn't a valid int, it exits the program with a failure.
func LookupIntSized(envVar string, base, bitSize int) (v int, ok bool) {
	assertNotInInit()
	val := os.Getenv(envVar)
	if val == "" {
		return 0, false
	}
	i, err := strconv.ParseInt(val, base, bitSize)
	if err == nil {
		v = int(i)
		noteEnv(envVar, val)
		return v, true
	}
	log.Fatalf("invalid integer environment variable %s: %v", envVar, val)
	panic("unreachable")
}

// LookupUintSized returns the unsigned integer value of the named environment
// value parsed in base and with a maximum bit size bitSize.
// The ok result is whether a value was set.
// If the value isn't a valid int, it exits the program with a failure.
func LookupUintSized(envVar string, base, bitSize int) (v uint, ok bool) {
	assertNotInInit()
	val := os.Getenv(envVar)
	if val == "" {
		return 0, false
	}
	i, err := strconv.ParseUint(val, base, bitSize)
	if err == nil {
		v = uint(i)
		noteEnv(envVar, val)
		return v, true
	}
	log.Fatalf("invalid unsigned integer environment variable %s: %v", envVar, val)
	panic("unreachable")
}

// UseWIPCode is whether TAILSCALE_USE_WIP_CODE is set to permit use
// of Work-In-Progress code.
func UseWIPCode() bool { return Bool("TAILSCALE_USE_WIP_CODE") }

// CanSSHD reports whether the Tailscale SSH server is allowed to run.
//
// If disabled (when this reports false), the SSH server won't start (won't
// intercept port 22) if previously configured to do so and any attempt to
// re-enable it will result in an error.
func CanSSHD() bool { return !Bool("TS_DISABLE_SSH_SERVER") }

// CanTaildrop reports whether the Taildrop feature is allowed to function.
//
// If disabled, Taildrop won't receive files regardless of user & server config.
func CanTaildrop() bool { return !Bool("TS_DISABLE_TAILDROP") }

// SSHPolicyFile returns the path, if any, to the SSHPolicy JSON file for development.
func SSHPolicyFile() string { return String("TS_DEBUG_SSH_POLICY_FILE") }

// SSHIgnoreTailnetPolicy reports whether to ignore the Tailnet SSH policy for development.
func SSHIgnoreTailnetPolicy() bool { return Bool("TS_DEBUG_SSH_IGNORE_TAILNET_POLICY") }

// TKASkipSignatureCheck reports whether to skip node-key signature checking for development.
func TKASkipSignatureCheck() bool { return Bool("TS_UNSAFE_SKIP_NKS_VERIFICATION") }

// App returns the tailscale app type of this instance, if set via
// TS_INTERNAL_APP env var. TS_INTERNAL_APP can be used to set app type for
// components that wrap tailscaled, such as containerboot. App type is intended
// to only be used to set known predefined app types, such as Tailscale
// Kubernetes Operator components.
func App() string {
	a := os.Getenv("TS_INTERNAL_APP")
	if a == kubetypes.AppConnector || a == kubetypes.AppEgressProxy || a == kubetypes.AppIngressProxy || a == kubetypes.AppIngressResource {
		return a
	}
	return ""
}

// CrashOnUnexpected reports whether the Tailscale client should panic
// on unexpected conditions. If TS_DEBUG_CRASH_ON_UNEXPECTED is set, that's
// used. Otherwise the default value is true for unstable builds.
func CrashOnUnexpected() bool {
	if v, ok := crashOnUnexpected().Get(); ok {
		return v
	}
	return version.IsUnstableBuild()
}

var crashOnUnexpected = RegisterOptBool("TS_DEBUG_CRASH_ON_UNEXPECTED")

// NoLogsNoSupport reports whether the client's opted out of log uploads and
// technical support.
func NoLogsNoSupport() bool {
	return Bool("TS_NO_LOGS_NO_SUPPORT")
}

var allowRemoteUpdate = RegisterBool("TS_ALLOW_ADMIN_CONSOLE_REMOTE_UPDATE")

// AllowsRemoteUpdate reports whether this node has opted-in to letting the
// Tailscale control plane initiate a Tailscale update (e.g. on behalf of an
// admin on the admin console).
func AllowsRemoteUpdate() bool { return allowRemoteUpdate() }

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

// ApplyDiskConfig returns a platform-specific config file of environment
// keys/values and applies them. On Linux and Unix operating systems, it's a
// no-op and always returns nil. If no platform-specific config file is found,
// it also returns nil.
//
// It exists primarily for Windows and macOS to make it easy to apply
// environment variables to a running service in a way similar to modifying
// /etc/default/tailscaled on Linux.
//
// On Windows, you use %ProgramData%\Tailscale\tailscaled-env.txt instead.
//
// On macOS, use one of:
//
//   - ~/Library/Containers/io.tailscale.ipn.macsys/Data/tailscaled-env.txt
//     for standalone macOS GUI builds
//   - ~/Library/Containers/io.tailscale.ipn.macos.network-extension/Data/tailscaled-env.txt
//     for App Store builds
//   - /etc/tailscale/tailscaled-env.txt for tailscaled-on-macOS (homebrew, etc)
func ApplyDiskConfig() (err error) {
	var f *os.File
	defer func() {
		if err != nil {
			// Stash away our return error for the healthcheck package to use.
			if f != nil {
				applyDiskConfigErr = fmt.Errorf("error parsing %s: %w", f.Name(), err)
			} else {
				applyDiskConfigErr = fmt.Errorf("error applying disk config: %w", err)
			}
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
		if version.IsSandboxedMacOS() { // the two GUI variants (App Store or separate download)
			// This will be user-visible as ~/Library/Containers/$VARIANT/Data/tailscaled-env.txt
			// where $VARIANT is "io.tailscale.ipn.macsys" for macsys (downloadable mac GUI builds)
			// or "io.tailscale.ipn.macos.network-extension" for App Store builds.
			return filepath.Join(os.Getenv("HOME"), "tailscaled-env.txt")
		} else {
			// Open source / homebrew variable, running tailscaled-on-macOS.
			return "/etc/tailscale/tailscaled-env.txt"
		}
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

// IPCVersion returns version.Long usually, unless TS_DEBUG_FAKE_IPC_VERSION is
// set, in which it contains that value. This is only used for weird development
// cases when testing mismatched versions and you want the client to act like it's
// compatible with the server.
func IPCVersion() string {
	if v := String("TS_DEBUG_FAKE_IPC_VERSION"); v != "" {
		return v
	}
	return version.Long()
}
