// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package posture registers support for device posture checking,
// reporting machine-specific information to the control plane
// when enabled by the user and tailnet.
package posture

import (
	"encoding/json"
	"net/http"

	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/posture"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
)

func init() {
	ipnext.RegisterExtension("posture", newExtension)
	ipnlocal.RegisterC2N("GET /posture/identity", handleC2NPostureIdentityGet)
}

func newExtension(logf logger.Logf, b ipnext.SafeBackend) (ipnext.Extension, error) {
	e := &extension{
		logf: logger.WithPrefix(logf, "posture: "),
	}
	return e, nil
}

type extension struct {
	logf logger.Logf

	// lastKnownHardwareAddrs is a list of the previous known hardware addrs.
	// Previously known hwaddrs are kept to work around an issue on Windows
	// where all addresses might disappear.
	// http://go/corp/25168
	lastKnownHardwareAddrs syncs.AtomicValue[[]string]
}

func (e *extension) Name() string             { return "posture" }
func (e *extension) Init(h ipnext.Host) error { return nil }
func (e *extension) Shutdown() error          { return nil }

func handleC2NPostureIdentityGet(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	e, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		http.Error(w, "posture extension not available", http.StatusInternalServerError)
		return
	}
	e.logf("c2n: GET /posture/identity received")

	res := tailcfg.C2NPostureIdentityResponse{}

	// Only collect posture identity if enabled on the client,
	// this will first check syspolicy, MDM settings like Registry
	// on Windows or defaults on macOS. If they are not set, it falls
	// back to the cli-flag, `--posture-checking`.
	choice, err := b.PolicyClient().GetPreferenceOption(pkey.PostureChecking, ptype.ShowChoiceByPolicy)
	if err != nil {
		e.logf(
			"c2n: failed to read PostureChecking from syspolicy, returning default from CLI: %s; got error: %s",
			b.Prefs().PostureChecking(),
			err,
		)
	}

	if choice.ShouldEnable(b.Prefs().PostureChecking()) {
		res.SerialNumbers, err = posture.GetSerialNumbers(b.PolicyClient(), e.logf)
		if err != nil {
			e.logf("c2n: GetSerialNumbers returned error: %v", err)
		}

		// TODO(tailscale/corp#21371, 2024-07-10): once this has landed in a stable release
		// and looks good in client metrics, remove this parameter and always report MAC
		// addresses.
		if r.FormValue("hwaddrs") == "true" {
			res.IfaceHardwareAddrs, err = e.getHardwareAddrs()
			if err != nil {
				e.logf("c2n: GetHardwareAddrs returned error: %v", err)
			}
		}
	} else {
		res.PostureDisabled = true
	}

	e.logf("c2n: posture identity disabled=%v reported %d serials %d hwaddrs", res.PostureDisabled, len(res.SerialNumbers), len(res.IfaceHardwareAddrs))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// getHardwareAddrs returns the hardware addresses for the machine. If the list
// of hardware addresses is empty, it will return the previously known hardware
// addresses. Both the current, and previously known hardware addresses might be
// empty.
func (e *extension) getHardwareAddrs() ([]string, error) {
	addrs, err := posture.GetHardwareAddrs()
	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		e.logf("getHardwareAddrs: got empty list of hwaddrs, returning previous list")
		return e.lastKnownHardwareAddrs.Load(), nil
	}

	e.lastKnownHardwareAddrs.Store(addrs)
	return addrs, nil
}
