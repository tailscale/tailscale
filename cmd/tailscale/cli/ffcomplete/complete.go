// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19 && !ts_omit_completion

// Package ffcomplete provides shell tab-completion of subcommands, flags and
// arguments for Go programs written with [ffcli].
//
// The shell integration scripts have been extracted from Cobra
// (https://cobra.dev/), whose authors deserve most of the credit for this work.
// These shell completion functions invoke `$0 completion __complete -- ...`
// which is wired up to [Complete].
package ffcomplete

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/cmd/tailscale/cli/ffcomplete/internal"
	"tailscale.com/tempfork/spf13/cobra"
)

// Inject adds the '__command' and 'completion' subcommands to the root command
// which provide the user with shell scripts for calling `__command` to provide
// tab-completion suggestions.
//
// root.Name needs to match the command that the user is tab-completing for the
// shell script to work as expected by default.
func Inject(root *ffcli.Command, usageFunc func(*ffcli.Command) string) {
	root.Subcommands = append(
		root.Subcommands,
		&ffcli.Command{
			Name:      "completion",
			ShortHelp: "Shell tab-completion scripts.",
			LongHelp:  fmt.Sprintf(cobra.UsageTemplate, root.Name),

			// Print help if run without args.
			Exec: func(ctx context.Context, args []string) error { return flag.ErrHelp },

			// Omit the '__complete' subcommand from the 'completion' help.
			UsageFunc: func(c *ffcli.Command) string {
				// Filter the subcommands to omit '__complete'.
				s := make([]*ffcli.Command, 0, len(c.Subcommands))
				for _, sub := range c.Subcommands {
					if !strings.HasPrefix(sub.Name, "__") {
						s = append(s, sub)
					}
				}

				// Swap in the filtered subcommands list for the rest of the call.
				defer func(r []*ffcli.Command) { c.Subcommands = r }(c.Subcommands)
				c.Subcommands = s

				// Render the usage.
				if usageFunc == nil {
					return ffcli.DefaultUsageFunc(c)
				}
				return usageFunc(c)
			},

			Subcommands: append(
				scriptCmds(root, usageFunc),
				&ffcli.Command{
					Name:      "__complete",
					ShortHelp: "__complete provides autocomplete suggestions to interactive shells.",
					UsageFunc: usageFunc,
					Exec: func(ctx context.Context, args []string) error {
						// Set up debug logging for the rest of this function call.
						if t := os.Getenv("BASH_COMP_DEBUG_FILE"); t != "" {
							tf, err := os.OpenFile(t, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
							if err != nil {
								return fmt.Errorf("opening debug file: %w", err)
							}
							defer func(origW io.Writer, origPrefix string, origFlags int) {
								log.SetOutput(origW)
								log.SetFlags(origFlags)
								log.SetPrefix(origPrefix)
								tf.Close()
							}(log.Writer(), log.Prefix(), log.Flags())
							log.SetOutput(tf)
							log.SetFlags(log.Lshortfile)
							log.SetPrefix("debug: ")
						}

						// Send back the results to the shell.
						words, dir, err := internal.Complete(root, args)
						if err != nil {
							dir = ShellCompDirectiveError
						}
						for _, word := range words {
							fmt.Println(word)
						}
						fmt.Println(":" + strconv.Itoa(int(dir)))
						return err
					},
				},
			),
		},
	)
}

// Flag registers a completion function for the flag in fs with given name.
// comp will always called with a 1-element slice.
//
// comp will be called to return suggestions when the user tries to tab-complete
// '--name=<TAB>' or '--name <TAB>' for the commands using fs.
func Flag(fs *flag.FlagSet, name string, comp CompleteFunc) {
	f := fs.Lookup(name)
	if f == nil {
		panic(fmt.Errorf("ffcomplete.Flag: flag %s not found", name))
	}
	if internal.CompleteFlags == nil {
		internal.CompleteFlags = make(map[*flag.Flag]CompleteFunc)
	}
	internal.CompleteFlags[f] = comp
}

// Args registers a completion function for the args of cmd.
//
// comp will be called to return suggestions when the user tries to tab-complete
// `prog <TAB>` or `prog subcmd arg1 <TAB>`, for example.
func Args(cmd *ffcli.Command, comp CompleteFunc) {
	if internal.CompleteCmds == nil {
		internal.CompleteCmds = make(map[*ffcli.Command]CompleteFunc)
	}
	internal.CompleteCmds[cmd] = comp
}
