// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package hostinfo

import (
	"bytes"
	"os"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/types/lazy"
)

func init() {
	RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
		if isPlan9V86() {
			hi.DeviceModel = copyV86DeviceModel
		}
	})
}

var isPlan9V86Cache lazy.SyncValue[bool]

// isPlan9V86 reports whether we're running in the wasm
// environment (https://github.com/copy/v86/).
func isPlan9V86() bool {
	return isPlan9V86Cache.Get(func() bool {
		v, _ := os.ReadFile("/dev/cputype")
		s, _, _ := strings.Cut(string(v), " ")
		if s != "PentiumIV/Xeon" {
			return false
		}

		v, _ = os.ReadFile("/dev/config")
		v, _, _ = bytes.Cut(v, []byte{'\n'})
		return string(v) == "# pcvm - small kernel used to run in vm"
	})
}
