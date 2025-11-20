// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Program addlicense adds a license header to a file.
// It is intended for use with 'go generate',
// so it has a slightly weird usage.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
)

var (
	file = flag.String("file", "", "file to modify")
)

func usage() {
	fmt.Fprint(os.Stderr, `
usage: addlicense -file FILE <subcommand args...>
`[1:])

	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
addlicense adds a Tailscale license to the beginning of file.

It is intended for use with 'go generate', so it also runs a subcommand,
which presumably creates the file.

Sample usage:

addlicense -file pull_strings.go stringer -type=pull
`[1:])
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if len(flag.Args()) == 0 {
		flag.Usage()
	}
	cmd := exec.Command(flag.Arg(0), flag.Args()[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	check(err)
	b, err := os.ReadFile(*file)
	check(err)
	f, err := os.OpenFile(*file, os.O_TRUNC|os.O_WRONLY, 0644)
	check(err)
	_, err = fmt.Fprint(f, license)
	check(err)
	_, err = f.Write(b)
	check(err)
	err = f.Close()
	check(err)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var license = `
// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

`[1:]
