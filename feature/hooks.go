// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package feature

import (
	"net/http"
	"net/url"

	"tailscale.com/types/logger"
	"tailscale.com/types/persist"
)

// HookCanAutoUpdate is a hook for the clientupdate package
// to conditionally initialize.
var HookCanAutoUpdate Hook[func() bool]

// CanAutoUpdate reports whether the current binary is built with auto-update
// support and, if so, whether the current platform supports it.
func CanAutoUpdate() bool {
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
