// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// mkversion gets version info from git and outputs a bunch of shell variables
// that get used elsewhere in the build system to embed version numbers into
// binaries.
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
