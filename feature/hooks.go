// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package feature

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"

	"tailscale.com/types/logger"
	"tailscale.com/types/persist"
)

// HookRegisterLogSinkFlags is a hook for the syslog feature to register
// its flags (such as tailscaled's --syslog) with the process's default
// flag set. If set, tailscaled calls it before flag parsing.
var HookRegisterLogSinkFlags Hook[func()]

// HookLogSink is a hook for the syslog feature to redirect the process's
// logs to an alternate sink. If set, tailscaled calls it once early in
// main, after flag parsing; on that first call, if the user requested an
// alternate sink, it points the standard library's default logger at that
// sink. It returns the sink, or nil if logs are not being redirected.
// Later callers (such as logpolicy, which otherwise writes its console
// copy of logs to stderr) use the returned writer to send their logs to
// the same place.
var HookLogSink Hook[func() io.Writer]

// HookCanAutoUpdate is a hook for the clientupdate package
// to conditionally initialize.
var HookCanAutoUpdate Hook[func() bool]

var testAllowAutoUpdate = sync.OnceValue(func() bool {
	return os.Getenv("TS_TEST_ALLOW_AUTO_UPDATE") == "1"
})

// CanAutoUpdate reports whether the current binary is built with auto-update
// support and, if so, whether the current platform supports it.
func CanAutoUpdate() bool {
	if testAllowAutoUpdate() {
		return true
	}
	if f, ok := HookCanAutoUpdate.GetOk(); ok {
		return f()
	}
	return false
}

// HookProxyFromEnvironment is a hook for feature/useproxy to register
// a function to use as http.ProxyFromEnvironment.
var HookProxyFromEnvironment Hook[func(*http.Request) (*url.URL, error)]

// HookProxyInvalidateCache is a hook for feature/useproxy to register
// [tshttpproxy.InvalidateCache].
var HookProxyInvalidateCache Hook[func()]

// HookProxyGetAuthHeader is a hook for feature/useproxy to register
// [tshttpproxy.GetAuthHeader].
var HookProxyGetAuthHeader Hook[func(*url.URL) (string, error)]

// HookProxySetSelfProxy is a hook for feature/useproxy to register
// [tshttpproxy.SetSelfProxy].
var HookProxySetSelfProxy Hook[func(...string)]

// HookProxySetTransportGetProxyConnectHeader is a hook for feature/useproxy to register
// [tshttpproxy.SetTransportGetProxyConnectHeader].
var HookProxySetTransportGetProxyConnectHeader Hook[func(*http.Transport)]

// HookTPMAvailable is a hook that reports whether a TPM device is supported
// and available.
var HookTPMAvailable Hook[func() bool]

var HookGenerateAttestationKeyIfEmpty Hook[func(p *persist.Persist, logf logger.Logf) (bool, error)]

// TPMAvailable reports whether a TPM device is supported and available.
func TPMAvailable() bool {
	if f, ok := HookTPMAvailable.GetOk(); ok {
		return f()
	}
	return false
}

// HookGetSSHHostKeyPublicStrings is a hook for the ssh/hostkeys package to
// provide SSH host key public strings to ipn/ipnlocal without ipnlocal needing
// to import golang.org/x/crypto/ssh.
var HookGetSSHHostKeyPublicStrings Hook[func(varRoot string, logf logger.Logf) ([]string, error)]

// HookHardwareAttestationAvailable is a hook that reports whether hardware
// attestation is supported and available.
var HookHardwareAttestationAvailable Hook[func() bool]

// HardwareAttestationAvailable reports whether hardware attestation is
// supported and available (TPM on Windows/Linux, Secure Enclave on macOS|iOS,
// KeyStore on Android)
func HardwareAttestationAvailable() bool {
	if f, ok := HookHardwareAttestationAvailable.GetOk(); ok {
		return f()
	}
	return false
}
