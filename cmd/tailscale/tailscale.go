// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The tailscale command is the Tailscale command-line client. It interacts
// with the tailscaled node agent.
package main // import "tailscale.com/cmd/tailscale"

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"tailscale.com/cmd/tailscale/cli"
	"tailscale.com/safesocket"
)

func parseWindowsLocalPort(args []string) ([]string, uint16, error) {
	index := -1
	for i := 0; i < len(args); i++ {
		if args[i] == "--windows-local-port" || args[i] == "-windows-local-port" {
			index = i
		}
	}
	if index == -1 {
		return args, safesocket.WindowsLocalPort, nil
	}
	port, err := strconv.Atoi(args[index+1])
	if err != nil {
		return args, safesocket.WindowsLocalPort, err
	}
	return append(args[:index], args[index+2:]...), uint16(port), nil
}

func main() {
	args := os.Args[1:]
	if name, _ := os.Executable(); strings.HasSuffix(filepath.Base(name), ".cgi") {
		args = []string{"web", "-cgi"}
	}

	args, windowsLocalPort, err := parseWindowsLocalPort(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	safesocket.WindowsLocalPort = windowsLocalPort

	if err := cli.Run(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
