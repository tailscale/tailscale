// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package localapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/util/httpm"
	"tailscale.com/version"
)

func init() {
	Register("serve-config", (*Handler).serveServeConfig)
}

func (h *Handler) serveServeConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case httpm.GET:
		if !h.PermitRead {
			http.Error(w, "serve config denied", http.StatusForbidden)
			return
		}
		config := h.b.ServeConfig()
		bts, err := json.Marshal(config)
		if err != nil {
			http.Error(w, "error encoding config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(bts)
		etag := hex.EncodeToString(sum[:])
		w.Header().Set("Etag", etag)
		w.Header().Set("Content-Type", "application/json")
		w.Write(bts)
	case httpm.POST:
		if !h.PermitWrite {
			http.Error(w, "serve config denied", http.StatusForbidden)
			return
		}
		configIn := new(ipn.ServeConfig)
		if err := json.NewDecoder(r.Body).Decode(configIn); err != nil {
			WriteErrorJSON(w, fmt.Errorf("decoding config: %w", err))
			return
		}

		// require a local admin when setting a path handler
		// TODO: roll-up this Windows-specific check into either PermitWrite
		// or a global admin escalation check.
		if err := authorizeServeConfigForGOOSAndUserContext(runtime.GOOS, configIn, h); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		etag := r.Header.Get("If-Match")
		if err := h.b.SetServeConfig(configIn, etag); err != nil {
			if errors.Is(err, ipnlocal.ErrETagMismatch) {
				http.Error(w, err.Error(), http.StatusPreconditionFailed)
				return
			}
			WriteErrorJSON(w, fmt.Errorf("updating config: %w", err))
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func authorizeServeConfigForGOOSAndUserContext(goos string, configIn *ipn.ServeConfig, h *Handler) error {
	switch goos {
	case "windows", "linux", "darwin", "illumos", "solaris":
	default:
		return nil
	}
	// Only check for local admin on tailscaled-on-mac (based on "sudo"
	// permissions). On sandboxed variants (MacSys and AppStore), tailscaled
	// cannot serve files outside of the sandbox and this check is not
	// relevant.
	if goos == "darwin" && version.IsSandboxedMacOS() {
		return nil
	}
	if !configIn.HasPathHandler() {
		return nil
	}
	if h.Actor.IsLocalAdmin(h.b.OperatorUserID()) {
		return nil
	}
	switch goos {
	case "windows":
		return errors.New("must be a Windows local admin to serve a path")
	case "linux", "darwin", "illumos", "solaris":
		return errors.New("must be root, or be an operator and able to run 'sudo tailscale' to serve a path")
	default:
		// We filter goos at the start of the func, this default case
		// should never happen.
		panic("unreachable")
	}
}
