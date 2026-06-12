// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wasmbuild contains the shared build flags and manifest layout
// used to produce the @tailscale/connect NPM package's main.wasm. It is
// imported both by cmd/tsconnect (which does the build) and by tests
// that verify the produced pkg/main.wasm matches what the current
// source tree would build (see tstest/integration/jswasmtest).
package wasmbuild

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"tailscale.com/feature/featuretags"
)

// baseTags are the non-featuretag build tags always set for the wasm
// build. Featuretag omits (ts_omit_*) are computed dynamically by
// [Tags] from [Keep] using the [featuretags] registry.
//
// Note: nethttpomithttp2 is intentionally NOT included: control/ts2021
// (since commit 1d93bdce2, Oct 2025) requires HTTP/2 from net/http's
// bundled implementation. Excluding it leaves the wasm client unable
// to negotiate with any control plane.
var baseTags = []string{
	"tailscale_go",
	"osusergo",
	"netgo",
	"omitidna",
	"omitpemdecrypt",
}

// Keep is the set of feature/featuretags tags the cmd/tsconnect/wasm
// build needs LINKED. Every other feature in [featuretags.Features] is
// excluded via its ts_omit_ build tag (computed by [Tags]).
// Transitive dependencies of entries in Keep are pulled in
// automatically via [featuretags.Requires].
//
// Adding an entry here grows the wasm bundle. Removing one strips it.
// The init() below panics if any entry is unknown to feature/featuretags,
// so a rename / removal in that registry fails loudly here.
//
// Notably absent (server-only or otherwise meaningless in a browser):
//   - "ssh": controls the SSH *server* (feature/ssh registers
//     ssh/tailssh). The wasm acts as an SSH *client* using
//     golang.org/x/crypto/ssh directly; no featuretag gates that.
//   - "portmapper", "debugportmapper": js/wasm has no UDP sockets,
//     can't speak NAT-PMP / PCP / UPnP.
//   - "captiveportal": the browser handles captive portal detection
//     in front of us.
//   - "syspolicy": no MDM in a browser.
//   - "drive", "taildrop", "peerapi*": no local filesystem.
//   - "clientupdate": no binary self-update.
//   - "dbus", "resolved", "networkmanager", "iptables", "linkspeed",
//     "linuxdnsfight", "listenrawdisco", "osrouter", "synology",
//     "systray", "tundevstats", "wakeonlan": OS integrations not
//     applicable to a browser-hosted client.
//   - "aws", "cloud", "kube", "bird", "appconnectors", "conn25",
//     "relayserver", "serve", "acme", "tap", "tpm", "doctor",
//     "advertiseroutes", "advertiseexitnode", "useroutes",
//     "useexitnode": server-side or otherwise out of scope for the
//     SSH-in-browser / fetch-in-browser use case.
var Keep = []featuretags.FeatureTag{
	"c2n",      // control-to-node mechanism the control client invokes
	"dns",      // MagicDNS resolution in-process
	"health",   // ipnstate/ipnlocal reference health warnables pervasively
	"ipnbus",   // notification bus for state/netmap callbacks
	"logtail",  // log upload (browser console + remote)
	"netstack", // userspace networking; wasm has no kernel TUN
}

func init() {
	for _, ft := range Keep {
		if _, ok := featuretags.Features[ft]; !ok {
			panic(fmt.Sprintf("wasmbuild.Keep references unknown feature tag %q; "+
				"did feature/featuretags rename or remove it?", ft))
		}
	}
}

// ProdLDFlags is the -ldflags value used in production wasm builds.
// -s strips the symbol table, -w strips DWARF, both to shrink the
// shipped artifact.
const ProdLDFlags = "-s -w"

// BuildInfoFile is the basename of the JSON manifest that build-pkg
// writes alongside main.wasm, recording the sha256 of the raw
// (pre-wasm-opt) go-build output. Tests use this to detect a stale
// pkg/main.wasm without having to re-run wasm-opt themselves.
const BuildInfoFile = "build-info.json"

// BuildInfo is the JSON contents of [BuildInfoFile].
type BuildInfo struct {
	// RawWasmSHA256 is the lowercase hex sha256 of the wasm bytes as
	// they came out of `go build` (before wasm-opt was run in place).
	RawWasmSHA256 string `json:"raw_wasm_sha256"`
}

// Tags returns the joined -tags value for the wasm build: [baseTags]
// plus a ts_omit_<feature> for every entry in [featuretags.Features]
// that is not transitively required by [Keep].
//
// The result is sorted so that the same source tree always produces
// the same string (and therefore the same wasm bytes, given identical
// inputs to `go build`).
func Tags() string {
	keep := map[featuretags.FeatureTag]bool{}
	for _, ft := range Keep {
		for dep := range featuretags.Requires(ft) {
			keep[dep] = true
		}
	}
	tags := slices.Clone(baseTags)
	for ft := range featuretags.Features {
		if ft == "" || !ft.IsOmittable() {
			continue
		}
		if !keep[ft] {
			tags = append(tags, ft.OmitTag())
		}
	}
	slices.Sort(tags)
	return strings.Join(tags, ",")
}

// ProdCommand returns an *exec.Cmd that runs `go build` for
// cmd/tsconnect/wasm with the production flags, writing the raw
// (pre-wasm-opt) wasm to outputPath. GOOS=js GOARCH=wasm is set in the
// command's environment. The caller is responsible for wiring
// Stdin/Stdout/Stderr and invoking Run.
//
// If goBin is empty, runtime.GOROOT()+"/bin/go" is used so that the
// build runs under the same toolchain that built the caller.
func ProdCommand(goBin, outputPath string) *exec.Cmd {
	if goBin == "" {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	cmd := exec.Command(goBin, "build",
		"-tags", Tags(),
		"-trimpath",
		"-ldflags", ProdLDFlags,
		"-o", outputPath,
		"tailscale.com/cmd/tsconnect/wasm",
	)
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	return cmd
}
