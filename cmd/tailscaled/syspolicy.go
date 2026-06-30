// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_syspolicy

package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"tailscale.com/util/syspolicy"
)

// syspolicyFile is the path to a JSON syspolicy file, set via the
// --syspolicy-file flag. An empty value disables file-based syspolicy.
var syspolicyFile string

// defaultSyspolicyFile returns the platform-specific default path for the
// --syspolicy-file flag. On Windows it sits next to the rest of Tailscale's
// machine state under %ProgramData%\Tailscale. On every other platform
// (Linux, the BSDs, illumos/Solaris, and tailscaled-without-the-GUI on
// macOS) it uses /etc/tailscale, which is where admin-provided
// configuration is conventionally placed.
//
// On Windows, when the file exists, its values take precedence over the
// HKLM registry-based platform store on a per-key basis (with the registry
// providing fallback values for keys the file does not set), because rsop
// merges later-registered same-scope sources over earlier ones.
func defaultSyspolicyFile() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "Tailscale", "syspolicy.json")
		}
		return ""
	}
	return "/etc/tailscale/syspolicy.json"
}

func init() {
	flag.StringVar(&syspolicyFile, "syspolicy-file", defaultSyspolicyFile(),
		"path to a JSON syspolicy file applied as a device-scope policy source; empty disables")
	loadSyspolicy.Set(func() {
		if syspolicyFile == "" {
			return
		}
		if err := syspolicy.LoadJSONPolicyFile("JSONFile", syspolicyFile); err != nil {
			log.Printf("%v", err)
		}
	})
}
