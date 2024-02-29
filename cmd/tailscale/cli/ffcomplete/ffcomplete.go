// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ffcomplete

import (
	"strings"

	"tailscale.com/cmd/tailscale/cli/ffcomplete/internal"
	"tailscale.com/tempfork/spf13/cobra"
)

type ShellCompDirective = cobra.ShellCompDirective

const (
	ShellCompDirectiveError         = cobra.ShellCompDirectiveError
	ShellCompDirectiveNoSpace       = cobra.ShellCompDirectiveNoSpace
	ShellCompDirectiveNoFileComp    = cobra.ShellCompDirectiveNoFileComp
	ShellCompDirectiveFilterFileExt = cobra.ShellCompDirectiveFilterFileExt
	ShellCompDirectiveFilterDirs    = cobra.ShellCompDirectiveFilterDirs
	ShellCompDirectiveKeepOrder     = cobra.ShellCompDirectiveKeepOrder
	ShellCompDirectiveDefault       = cobra.ShellCompDirectiveDefault
)

// CompleteFunc is used to return tab-completion suggestions to the user as they
// are typing command-line instructions. It returns the list of things to
// suggest and an additional directive to the shell about what extra
// functionality to enable.
type CompleteFunc = internal.CompleteFunc

// LastArg returns the last element of args, or the empty string if args is
// empty.
func LastArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[len(args)-1]
}

// Fixed returns a CompleteFunc which suggests the given words.
func Fixed(words ...string) CompleteFunc {
	return func(args []string) ([]string, cobra.ShellCompDirective, error) {
		match := LastArg(args)
		matches := make([]string, 0, len(words))
		for _, word := range words {
			if strings.HasPrefix(word, match) {
				matches = append(matches, word)
			}
		}
		return matches, cobra.ShellCompDirectiveNoFileComp, nil
	}
}

// FilesWithExtensions returns a CompleteFunc that tells the shell to limit file
// suggestions to those with the given extensions.
func FilesWithExtensions(exts ...string) CompleteFunc {
	return func(args []string) ([]string, cobra.ShellCompDirective, error) {
		return exts, cobra.ShellCompDirectiveFilterFileExt, nil
	}
}
