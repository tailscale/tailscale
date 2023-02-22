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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=0 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=riscv64 (was riscv64)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=0 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=freebsd (was freebsd)
GOROOT=/goroot (was <nil>)
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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "test",
				"-trimpath",
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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=0 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=windows (was windows)
GOROOT=/goroot (was <nil>)
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
			name:         "darwin_arm64_to_darwin_arm64",
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "darwin",
			nativeGOARCH: "arm64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=arm64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=darwin (was <nil>)
GOROOT=/goroot (was <nil>)
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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was amd64)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=darwin (was <nil>)
GOROOT=/goroot (was <nil>)
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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=arm64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=ios (was ios)
GOROOT=/goroot (was <nil>)
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
				"GOOS":                              "darwin",
				"GOARCH":                            "amd64",
				"XCODE_VERSION_ACTUAL":              "1300",
				"DEPLOYMENT_TARGET_CLANG_FLAG_NAME": "mmacosx-version-min",
				"MACOSX_DEPLOYMENT_TARGET":          "11.3",
				"DEPLOYMENT_TARGET_CLANG_ENV_NAME":  "MACOSX_DEPLOYMENT_TARGET",
				"SDKROOT":                           "/my/sdk/root",
			},
			argv:         []string{"gocross", "build", "./cmd/tailcontrol"},
			goroot:       "/goroot",
			nativeGOOS:   "darwin",
			nativeGOARCH: "arm64",

			envDiff: `CC=cc (was <nil>)
CGO_CFLAGS=-O3 -std=gnu11 -mmacosx-version-min=11.3 -isysroot /my/sdk/root -arch x86_64 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS=-mmacosx-version-min=11.3 -isysroot /my/sdk/root -arch x86_64 (was <nil>)
GOARCH=amd64 (was amd64)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=darwin (was darwin)
GOROOT=/goroot (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,omitidna,omitpemdecrypt",
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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/special/toolchain/path (was <nil>)
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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
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
CGO_CFLAGS=-O3 -std=gnu11 (was <nil>)
CGO_ENABLED=1 (was <nil>)
CGO_LDFLAGS= (was <nil>)
GOARCH=amd64 (was <nil>)
GOARM=5 (was <nil>)
GOMIPS=softfloat (was <nil>)
GOOS=linux (was <nil>)
GOROOT=/goroot (was <nil>)
TS_LINK_FAIL_REFLECT=0 (was <nil>)`,
			wantArgv: []string{
				"gocross", "build",
				"-trimpath",
				"-tags=tailscale_go,osusergo,netgo",
				"-ldflags", "-X tailscale.com/version.longStamp=1.2.3-long -X tailscale.com/version.shortStamp=1.2.3 -X tailscale.com/version.gitCommitStamp=abcd -X tailscale.com/version.extraGitCommitStamp=defg '-extldflags=-static -L /my/glibc/path'",
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
