// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"reflect"
	"testing"

	"tailscale.com/version/mkversion"
)

var fakeVersion = mkversion.VersionInfo{
	Short:     "1.2.3",
	Long:      "1.2.3-long",
	GitHash:   "abcd",
	OtherHash: "defg",
	Xcode:     "100.2.3",
	Winres:    "1,2,3,0",
}

func TestAutoflags(t *testing.T) {
	tests := []struct {
		// name convention: "<hostos>_<hostarch>_to_<targetos>_<targetarch>_<anything else?>"
		name         string
		env          map[string]string
		argv         []string
		goroot       string
		nativeGOOS   string
		nativeGOARCH string

		wantEnv  map[string]string
		envDiff  string
		wantArgv []string
	}{
		{
			name:         "linux_amd64_to_linux_amd64",
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,osusergo,netgo",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg '-extldflags=-static'",
				"./cmd/tailcontrol",
			},
		},
		{
			name:         "install_linux_amd64_to_linux_amd64",
			argv:         []string{"gocross", "install", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "install",
				"-trimpath",
				"-tags=tailscale_go,osusergo,netgo",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg '-extldflags=-static'",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "linux_amd64_to_linux_riscv64",
			env: map[string]string{
				"GOARCH": "riscv64",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=0 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=riscv64 (was riscv64)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,osusergo,netgo",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg '-extldflags=-static'",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "linux_amd64_to_freebsd_amd64",
			env: map[string]string{
				"GOOS": "freebsd",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=0 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=freebsd (was freebsd)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg",
				"./cmd/tailcontrol",
			},
		},
		{
			name:         "linux_amd64_to_linux_amd64_race",
			argv:         []string{"gocross", "test", "-race", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "test",
				"-tags=tailscale_go,osusergo,netgo",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg '-extldflags=-static'",
				"-race",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "linux_amd64_to_windows_amd64",
			env: map[string]string{
				"GOOS": "windows",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=0 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=windows (was windows)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg -H windows -s",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "linux_amd64_to_android_amd64",
			env: map[string]string{
				"GOOS": "android",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=0 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=android (was android)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "linux_amd64_to_android_amd64_cgo",
			env: map[string]string{
				"GOOS":        "android",
				"CGO_ENABLED": "1",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was 1)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=android (was android)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg",
				"./cmd/tailcontrol",
			},
		},
		{
			name:         "darwin_arm64_to_darwin_arm64",
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "darwin",
			nativeGOARCH: "arm64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=arm64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=darwin (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,omitidna,omitpemdecrypt",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "darwin_arm64_to_darwin_arm64_empty_goos",
			argv: []string{"gocross", "build", "./cmd/tailcontrol"},
			env: map[string]string{
				"GOOS": "",
			},
			goroot:       "/goroot",
			nativeGOOS:   "darwin",
			nativeGOARCH: "arm64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=arm64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=darwin (was )
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,omitidna,omitpemdecrypt",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "darwin_arm64_to_darwin_arm64_empty_goarch",
			argv: []string{"gocross", "build", "./cmd/tailcontrol"},
			env: map[string]string{
				"GOARCH": "",
			},
			goroot:       "/goroot",
			nativeGOOS:   "darwin",
			nativeGOARCH: "arm64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=arm64 (was )
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=darwin (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,omitidna,omitpemdecrypt",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "darwin_arm64_to_darwin_amd64",
			env: map[string]string{
				"GOARCH": "amd64",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "darwin",
			nativeGOARCH: "arm64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was amd64)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=darwin (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,omitidna,omitpemdecrypt",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "darwin_arm64_to_ios_arm64",
			env: map[string]string{
				"GOOS": "ios",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "darwin",
			nativeGOARCH: "arm64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=arm64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=ios (was ios)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=1 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,omitidna,omitpemdecrypt",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "darwin_arm64_to_darwin_amd64_xcode",
			env: map[string]string{
				"GOOS":                     "darwin",
				"GOARCH":                   "amd64",
				"XCODE_VERSION_ACTUAL":     "1300",
				"MACOSX_DEPLOYMENT_TARGET": "11.3",
				"SDKROOT":                  "/my/sdk/root",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "darwin",
			nativeGOARCH: "arm64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g -mmacosx-version-min=11.3 -isysroot /my/sdk/root -arch x86_64 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS=-mmacosx-version-min=11.3 -isysroot /my/sdk/root -arch x86_64 (was <nil>)
GOARCH=amd64 (was amd64)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=darwin (was darwin)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,omitidna,omitpemdecrypt,ts_macext",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg -w",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "darwin_amd64_to_ios_arm64_xcode",
			env: map[string]string{
				"GOOS":                       "ios",
				"GOARCH":                     "arm64",
				"XCODE_VERSION_ACTUAL":       "1300",
				"IPHONEOS_DEPLOYMENT_TARGET": "15.0",
				"SDKROOT":                    "/my/sdk/root",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "darwin",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g -miphoneos-version-min=15.0 -isysroot /my/sdk/root -arch arm64 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS=-miphoneos-version-min=15.0 -isysroot /my/sdk/root -arch arm64 (was <nil>)
GOARCH=arm64 (was arm64)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=ios (was ios)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=1 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,omitidna,omitpemdecrypt,ts_macext",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg -w",
				"./cmd/tailcontrol",
			},
		},
		{
			name:         "linux_amd64_to_linux_amd64_in_goroot",
			argv:         []string{"go", "build", "./cmd/tailcontrol"},
			goroot:       "/special/toolchain/path",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/special/toolchain/path (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"go", "build",
				"-trimpath",
				"-tags=tailscale_go,osusergo,netgo",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg '-extldflags=-static'",
				"./cmd/tailcontrol",
			},
		},
		{
			name:         "linux_list_amd64_to_linux_amd64",
			argv:         []string{"gocross", "list", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "list",
				"-trimpath",
				"-tags=tailscale_go,osusergo,netgo",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg '-extldflags=-static'",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "linux_amd64_to_linux_amd64_with_extra_glibc_path",
			env: map[string]string{
				"GOCROSS_GLIBC_DIR": "/my/glibc/path",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,osusergo,netgo",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg '-extldflags=-static -L /my/glibc/path'",
				"./cmd/tailcontrol",
			},
		},
		{
			name: "linux_amd64_to_linux_amd64_go_run_tags",

			argv:         []string{"go", "run", "./cmd/mkctr", "--tags=foo"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"go", "run",
				"-trimpath",
				"-tags=tailscale_go,osusergo,netgo",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg '-extldflags=-static'",
				"./cmd/mkctr",
				"--tags=foo",
			},
		},
		{
			name: "linux_amd64_to_linux_amd64_custom_toolchain",
			env: map[string]string{
				"GOTOOLCHAIN": "go1.30rc5",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "linux",
			nativeGOARCH: "amd64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -g (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
GOTOOLCHAIN=local (was go1.30rc5)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,osusergo,netgo",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg '-extldflags=-static'",
				"./cmd/tailcontrol",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			getver := func() mkversion.VersionInfo { return fakeVersion }
			env := newEnvironmentForTest(test.env, nil, nil)

			gotArgv, env, err := autoflagsForTest(test.argv, env, test.goroot, test.nativeGOOS, test.nativeGOARCH, getver)
			if err != nil {
				t.Fatalf("newAutoflagsForTest failed: %v", err)
			}

			if diff := env.Diff(); diff != test.envDiff {
				t.Errorf("wrong environment diff, got:\n%s\n\nwant:\n%s", diff, test.envDiff)
			}
			if !reflect.DeepEqual(gotArgv, test.wantArgv) {
				t.Errorf("wrong argv:\n  got : %s\n  want: %s", formatArgv(gotArgv), formatArgv(test.wantArgv))
			}
		})
	}
}

func TestExtractTags(t *testing.T) {
	s := func(ss ...string) []string { return ss }
	tests := []struct {
		name string
		cmd  string
		in   []string
		filt []string // want filtered
		tags []string // want tags
	}{
		{
			name: "one_hyphen_tags",
			cmd:  "build",
			in:   s("foo", "-tags=a,b", "bar"),
			filt: s("foo", "bar"),
			tags: s("a", "b"),
		},
		{
			name: "two_hyphen_tags",
			cmd:  "build",
			in:   s("foo", "--tags=a,b", "bar"),
			filt: s("foo", "bar"),
			tags: s("a", "b"),
		},
		{
			name: "one_hypen_separate_arg",
			cmd:  "build",
			in:   s("foo", "-tags", "a,b", "bar"),
			filt: s("foo", "bar"),
			tags: s("a", "b"),
		},
		{
			name: "two_hypen_separate_arg",
			cmd:  "build",
			in:   s("foo", "--tags", "a,b", "bar"),
			filt: s("foo", "bar"),
			tags: s("a", "b"),
		},
		{
			name: "equal_empty",
			cmd:  "build",
			in:   s("foo", "--tags=", "bar"),
			filt: s("foo", "bar"),
			tags: s(),
		},
		{
			name: "arg_empty",
			cmd:  "build",
			in:   s("foo", "--tags", "", "bar"),
			filt: s("foo", "bar"),
			tags: s(),
		},
		{
			name: "arg_empty_truncated",
			cmd:  "build",
			in:   s("foo", "--tags"),
			filt: s("foo"),
			tags: s(),
		},
		{
			name: "go_run_with_program_tags",
			cmd:  "run",
			in:   s("--foo", "--tags", "bar", "my/package/name", "--tags", "qux"),
			filt: s("--foo", "my/package/name", "--tags", "qux"),
			tags: s("bar"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filt, tags := extractTags(tt.cmd, tt.in)
			if !reflect.DeepEqual(filt, tt.filt) {
				t.Errorf("extractTags(%q, %q) filtered = %q; want %q", tt.cmd, tt.in, filt, tt.filt)
			}
			if !reflect.DeepEqual(tags, tt.tags) {
				t.Errorf("extractTags(%q, %q) tags = %q; want %q", tt.cmd, tt.in, tags, tt.tags)
			}
		})
	}
}
