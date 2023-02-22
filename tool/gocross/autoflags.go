// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"runtime"
	"strings"

	"tailscale.com/version/mkversion"
)

// Autoflags adjusts the commandline argv into a new commandline
// newArgv and envvar alterations in env.
func Autoflags(argv []string, goroot string) (newArgv []string, env *Environment, err error) {
	return autoflagsForTest(argv, NewEnvironment(), goroot, runtime.GOOS, runtime.GOARCH, mkversion.Info)
}

func autoflagsForTest(argv []string, env *Environment, goroot, nativeGOOS, nativeGOARCH string, getVersion func() mkversion.VersionInfo) (newArgv []string, newEnv *Environment, err error) {
	// This is where all our "automatic flag injection" decisions get
	// made. Modifying this code will modify the environment variables
	// and commandline flags that the final `go` tool invocation will
	// receive.
	//
	// When choosing between making this code concise or readable,
	// please err on the side of being readable. Our build
	// environments are relatively complicated by Go standards, and we
	// want to keep it intelligible and malleable for our future
	// selves.
	var (
		subcommand = ""

		targetOS    = env.Get("GOOS", nativeGOOS)
		targetArch  = env.Get("GOARCH", nativeGOARCH)
		buildFlags  = []string{"-trimpath"}
		cgoCflags   = []string{"-O3", "-std=gnu11"}
		cgoLdflags  []string
		ldflags     []string
		tags        = []string{"tailscale_go"}
		cgo         = false
		failReflect = false
	)
	if len(argv) > 1 {
		subcommand = argv[1]
	}

	switch subcommand {
	case "build", "env", "install", "run", "test", "list":
	default:
		return argv, env, nil
	}

	vi := getVersion()
	ldflags = []string{
		"-X", "tailscale.com/version.longStamp=" + vi.Long,
		"-X", "tailscale.com/version.shortStamp=" + vi.Short,
		"-X", "tailscale.com/version.gitCommitStamp=" + vi.GitHash,
		"-X", "tailscale.com/version.extraGitCommitStamp=" + vi.OtherHash,
	}

	switch targetOS {
	case "linux":
		// Getting Go to build a static binary with cgo enabled is a
		// minor ordeal. The incantations you apparently need are
		// documented at: https://github.com/golang/go/issues/26492
		tags = append(tags, "osusergo", "netgo")
		cgo = targetOS == nativeGOOS && targetArch == nativeGOARCH
		// When in a Nix environment, the gcc package is built with only dynamic
		// versions of glibc. You can get a static version of glibc via
		// pkgs.glibc.static, but then you are reliant on Nix's gcc wrapper
		// magic to inject that as a -L path to linker invocations.
		//
		// We can't rely on that magic linker flag injection, because that
		// injection breaks redo's go machinery for dynamic go+cgo linking due
		// to flag ordering issues that we can't easily fix (since the nix
		// machinery controls the flag ordering, not us).
		//
		// So, instead, we unset NIX_LDFLAGS in our nix shell, which disables
		// the magic linker flag passing; and we have shell.nix drop the path to
		// the static glibc files in GOCROSS_GLIBC_DIR. Finally, we reinject it
		// into the build process here, so that the linker can find static glibc
		// and complete a static-with-cgo linkage.
		extldflags := []string{"-static"}
		if glibcDir := env.Get("GOCROSS_GLIBC_DIR", ""); glibcDir != "" {
			extldflags = append(extldflags, "-L", glibcDir)
		}
		// -extldflags, when it contains multiple external linker flags, must be
		// quoted in its entirety as a member of -ldflags. Source:
		// https://github.com/golang/go/issues/6234
		ldflags = append(ldflags, fmt.Sprintf("'-extldflags=%s'", strings.Join(extldflags, " ")))
	case "windowsgui":
		// Fake GOOS that translates to "windows, but building GUI .exes not console .exes"
		targetOS = "windows"
		ldflags = append(ldflags, "-H", "windowsgui", "-s")
	case "windows":
		ldflags = append(ldflags, "-H", "windows", "-s")
	case "ios":
		failReflect = true
		fallthrough
	case "darwin":
		cgo = nativeGOOS == "darwin"
		tags = append(tags, "omitidna", "omitpemdecrypt")
		if env.IsSet("XCODE_VERSION_ACTUAL") {
			var xcodeFlags []string
			// Minimum OS version being targeted, results in
			// e.g. -mmacosx-version-min=11.3
			minOSKey := env.Get("DEPLOYMENT_TARGET_CLANG_FLAG_NAME", "")
			minOSVal := env.Get(env.Get("DEPLOYMENT_TARGET_CLANG_ENV_NAME", ""), "")
			xcodeFlags = append(xcodeFlags, fmt.Sprintf("-%s=%s", minOSKey, minOSVal))

			// Target-specific SDK directory. Must be passed as two
			// words ("-isysroot PATH", not "-isysroot=PATH").
			xcodeFlags = append(xcodeFlags, "-isysroot", env.Get("SDKROOT", ""))

			// What does clang call the target GOARCH?
			var clangArch string
			switch targetArch {
			case "amd64":
				clangArch = "x86_64"
			case "arm64":
				clangArch = "arm64"
			default:
				return nil, nil, fmt.Errorf("unsupported GOARCH=%q when building from Xcode", targetArch)
			}
			xcodeFlags = append(xcodeFlags, "-arch", clangArch)
			cgoCflags = append(cgoCflags, xcodeFlags...)
			cgoLdflags = append(cgoLdflags, xcodeFlags...)
			ldflags = append(ldflags, "-w")
		}
	}

	// Finished computing the settings we want. Generate the modified
	// commandline and environment modifications.
	newArgv = append(newArgv, argv[:2]...) // Program name and `go` tool subcommand
	newArgv = append(newArgv, buildFlags...)
	if len(tags) > 0 {
		newArgv = append(newArgv, fmt.Sprintf("-tags=%s", strings.Join(tags, ",")))
	}
	if len(ldflags) > 0 {
		newArgv = append(newArgv, "-ldflags", strings.Join(ldflags, " "))
	}
	newArgv = append(newArgv, argv[2:]...)

	env.Set("GOOS", targetOS)
	env.Set("GOARCH", targetArch)
	env.Set("GOARM", "5") // TODO: fix, see go/internal-bug/3092
	env.Set("GOMIPS", "softfloat")
	env.Set("CGO_ENABLED", boolStr(cgo))
	env.Set("CGO_CFLAGS", strings.Join(cgoCflags, " "))
	env.Set("CGO_LDFLAGS", strings.Join(cgoLdflags, " "))
	env.Set("CC", "cc")
	env.Set("TS_LINK_FAIL_REFLECT", boolStr(failReflect))
	env.Set("GOROOT", goroot)

	if subcommand == "env" {
		return argv, env, nil
	}

	return newArgv, env, nil
}

// boolStr formats v as a string 0 or 1.
// Used because CGO_ENABLED doesn't strconv.ParseBool, so
// strconv.FormatBool breaks.
func boolStr(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// formatArgv formats a []string similarly to %v, but quotes each
// string so that the reader can clearly see each array element.
func formatArgv(v []string) string {
	var ret strings.Builder
	ret.WriteByte('[')
	for _, s := range v {
		fmt.Fprintf(&ret, "%q ", s)
	}
	ret.WriteByte(']')
	return ret.String()
}
