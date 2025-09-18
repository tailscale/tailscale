// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package prompt provides a simple way to prompt the user for input.
package prompt

import (
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
)

// YesNo takes a question and prompts the user to answer the
// question with a yes or no. It appends a [y/n] to the message.
//
// If there is no TTY on both Stdin and Stdout, assume that we're in a script
// and return the dflt result.
func YesNo(msg string, dflt bool) bool {
	if !(isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())) {
		return dflt
	}
	if dflt {
		fmt.Print(msg + " [Y/n] ")
	} else {
		fmt.Print(msg + " [y/N] ")
	}
	var resp string
	fmt.Scanln(&resp)
	resp = strings.ToLower(resp)
	switch resp {
	case "y", "yes", "sure":
		return true
	case "":
		return dflt
	}
	return false
}
