// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// mkversion gets version info from git and outputs a bunch of shell variables
// that get used elsewhere in the build system to embed version numbers into
// binaries.
//
// If TS_VERSION_LONG and TS_VERSION_GIT_HASH are set, the version comes from
// the environment instead of git and no checkout is needed. That is also a
// convenient way to see everything derived from a given version:
//
//	TS_VERSION_LONG=1.99.5-t8895cec85 TS_VERSION_GIT_HASH=8895cec85... go run ./cmd/mkversion
//
// See tailscale.com/version/mkversion.InfoFrom for the full set of variables.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/version/mkversion"
)

func main() {
	prefix := ""
	if len(os.Args) > 1 {
		if os.Args[1] == "--export" {
			prefix = "export "
		} else {
			fmt.Println("usage: mkversion [--export|-h|--help]")
			os.Exit(1)
		}
	}

	var b bytes.Buffer
	io.WriteString(&b, mkversion.Info().String())
	// Copyright and the client capability are not part of the version
	// information, but similarly used in Xcode builds to embed in the metadata,
	// thus generate them now.
	copyright := fmt.Sprintf("Copyright © %d Tailscale Inc. All Rights Reserved.", time.Now().Year())
	fmt.Fprintf(&b, "VERSION_COPYRIGHT=%q\n", copyright)
	fmt.Fprintf(&b, "VERSION_CAPABILITY=%d\n", tailcfg.CurrentCapabilityVersion)
	s := bufio.NewScanner(&b)
	for s.Scan() {
		fmt.Println(prefix + s.Text())
	}
}
