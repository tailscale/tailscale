// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package prompt provides a simple way to prompt the user for input.
package prompt

import (
	"fmt"
	"strings"
)

// YesNo takes a question and prompts the user to answer the
// question with a yes or no. It appends a [y/n] to the message.
func YesNo(msg string) bool {
	fmt.Print(msg + " [y/n] ")
	var resp string
	fmt.Scanln(&resp)
	resp = strings.ToLower(resp)
	switch resp {
	case "y", "yes", "sure":
		return true
	}
	return false
}
