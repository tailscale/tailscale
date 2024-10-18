// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"cmp"
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

		cc          = "cc"
		targetOS    = cmp.Or(env.Get("GOOS", ""), nativeGOOS)
		targetArch  = cmp.Or(env.Get("GOARCH", ""), nativeGOARCH)
		buildFlags  = []string{}
		cgoCflags   = []string{"-O3", "-std=gnu11", "-g"}
		cgoLdflags  []string
		ldflags     []string
		tags        = []string{"tailscale_go"}
		cgo         = false
		failReflect = false
	)
	if len(argv) > 1 {
		subcommand = argv[1]
	}

	if subcommand != "test" {
		buildFlags = append(buildFlags, "-trimpath")
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
	case "android":
		cgo = env.Get("CGO_ENABLED", "0") == "1"
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
	case "windowsdll":
		// Fake GOOS that translates to "windows, but building .dlls not .exes"
		targetOS = "windows"
		cgo = true
		buildFlags = append(buildFlags, "-buildmode=c-shared")
		ldflags = append(ldflags, "-H", "windows", "-s")
		cgoLdflags = append(cgoLdflags, "-static")
		var mingwArch string
		switch targetArch {
		case "amd64":
			mingwArch = "x86_64"
		case "386":
			mingwArch = "i686"
		default:
			return nil, nil, fmt.Errorf("unsupported GOARCH=%q when building with cgo", targetArch)
		}
		cc = fmt.Sprintf("%s-w64-mingw32-gcc", mingwArch)
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
			// If we're building via Xcode, we must be making the extension
			// version (as opposed to tailscaled on Mac).
			tags = append(tags, "ts_macext")

			var xcodeFlags []string
			// Minimum OS version being targeted, results in
			// e.g. -mmacosx-version-min=11.3, -miphoneos-version-min=15.0
			switch {
			case env.IsSet("XROS_DEPLOYMENT_TARGET"):
				if env.Get("TARGET_DEVICE_PLATFORM_NAME", "") == "xrsimulator" {
					xcodeFlags = append(xcodeFlags, "-mtargetos=xros"+env.Get("XROS_DEPLOYMENT_TARGET", "")+"-simulator")
				} else {
					xcodeFlags = append(xcodeFlags, "-mtargetos=xros"+env.Get("XROS_DEPLOYMENT_TARGET", ""))
				}
			case env.IsSet("IPHONEOS_DEPLOYMENT_TARGET"):
				if env.Get("TARGET_DEVICE_PLATFORM_NAME", "") == "iphonesimulator" {
					xcodeFlags = append(xcodeFlags, "-miphonesimulator-version-min="+env.Get("IPHONEOS_DEPLOYMENT_TARGET", ""))
				} else {
					xcodeFlags = append(xcodeFlags, "-miphoneos-version-min="+env.Get("IPHONEOS_DEPLOYMENT_TARGET", ""))
				}
			case env.IsSet("MACOSX_DEPLOYMENT_TARGET"):
				xcodeFlags = append(xcodeFlags, "-mmacosx-version-min="+env.Get("MACOSX_DEPLOYMENT_TARGET", ""))
			case env.IsSet("TVOS_DEPLOYMENT_TARGET"):
				if env.Get("TARGET_DEVICE_PLATFORM_NAME", "") == "appletvsimulator" {
					xcodeFlags = append(xcodeFlags, "-mtvos-simulator-version-min="+env.Get("TVOS_DEPLOYMENT_TARGET", ""))
				} else {
					xcodeFlags = append(xcodeFlags, "-mtvos-version-min="+env.Get("TVOS_DEPLOYMENT_TARGET", ""))
				}
			default:
				return nil, nil, fmt.Errorf("invoked by Xcode but couldn't figure out deployment target. Did Xcode change its envvars again?")
			}

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

	filteredArgvPostSubcmd, originalTags := extractTags(argv[1], argv[2:])

	newArgv = append(newArgv, buildFlags...)
	tags = append(tags, originalTags...)
	if len(tags) > 0 {
		newArgv = append(newArgv, fmt.Sprintf("-tags=%s", strings.Join(tags, ",")))
	}
	if len(ldflags) > 0 {
		newArgv = append(newArgv, "-ldflags", strings.Join(ldflags, " "))
	}
	newArgv = append(newArgv, filteredArgvPostSubcmd...)

	env.Set("GOOS", targetOS)
	env.Set("GOARCH", targetArch)
	if !env.IsSet("GOARM") {
		env.Set("GOARM", "5") // TODO: fix, see go/internal-bug/3092
	}
	env.Set("GOMIPS", "softfloat")
	env.Set("CGO_ENABLED", boolStr(cgo))
	env.Set("CGO_CFLAGS", strings.Join(cgoCflags, " "))
	env.Set("CGO_LDFLAGS", strings.Join(cgoLdflags, " "))
	env.Set("CC", cc)
	env.Set("TS_LINK_FAIL_REFLECT", boolStr(failReflect))
	env.Set("GOROOT", goroot)
	env.Set("GOTOOLCHAIN", "local")

	if subcommand == "env" {
		return argv, env, nil
	}

	return newArgv, env, nil
}

// extractTags parses out "-tags=foo,bar" (or double hyphen or "-tags",
// "foo,bar") in its various forms and returns v filtered to remove the 0, 1 or
// 2 build tag elements, then the tags parsed, split on commas ("foo", "bar").
func extractTags(gocmd string, v []string) (filtered, tags []string) {
	for len(v) > 0 {
		e := v[0]
		if strings.HasPrefix(e, "--tags=") {
			e = e[1:] // remove one of the hyphens for the next line
		}
		if suf, ok := strings.CutPrefix(e, "-tags="); ok {
			v = v[1:]
			if suf != "" {
				tags = strings.Split(suf, ",")
			}
			continue
		}
		if e == "-tags" || e == "--tags" {
			v = v[1:]
			if len(v) > 0 {
				tagStr := v[0]
				v = v[1:]
				if tagStr != "" {
					tags = strings.Split(tagStr, ",")
				}
			}
			continue
		}
		if gocmd == "run" && !strings.HasPrefix(e, "-") {
			// go run can include arguments to pass to the program
			// being run. They all appear after the name of the
			// package or Go file to run, so when we hit the first
			// non-flag positional argument, stop extracting tags and
			// wrap up.
			filtered = append(filtered, v...)
			break
		}
		filtered = append(filtered, e)
		v = v[1:]
	}
	return filtered, tags
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
