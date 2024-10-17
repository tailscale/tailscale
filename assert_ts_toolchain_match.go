// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build tailscale_go

package tailscaleroot

import (
	"fmt"
	"os"
	"strings"
)

func init() {
	tsRev, ok := tailscaleToolchainRev()
	if !ok {
		panic("binary built with tailscale_go build tag but failed to read build info or find tailscale.toolchain.rev in build info")
	}
	want := strings.TrimSpace(GoToolchainRev)
	if tsRev != want {
		if os.Getenv("TS_PERMIT_TOOLCHAIN_MISMATCH") == "1" {
			fmt.Fprintf(os.Stderr, "tailscale.toolchain.rev = %q, want %q; but ignoring due to TS_PERMIT_TOOLCHAIN_MISMATCH=1\n", tsRev, want)
			return
		}
		panic(fmt.Sprintf("binary built with tailscale_go build tag but Go toolchain %q doesn't match github.com/tailscale/tailscale expected value %q; override this failure with TS_PERMIT_TOOLCHAIN_MISMATCH=1", tsRev, want))
	}
}
