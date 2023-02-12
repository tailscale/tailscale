// mkversion gets version info from git and outputs a bunch of shell
// variables that get used elsewhere in the redo build system to embed
// version numbers into binaries.

//go:build ignore

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"tailscale.io/version"
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
	io.WriteString(&b, version.Info().String())
	s := bufio.NewScanner(&b)
	for s.Scan() {
		fmt.Println(prefix + s.Text())
	}
}
