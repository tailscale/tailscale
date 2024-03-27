// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19 && !ts_omit_completion_scripts

package ffcomplete

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/tempfork/spf13/cobra"
)

func scriptCmds(root *ffcli.Command, usageFunc func(*ffcli.Command) string) []*ffcli.Command {
	const (
		compCmd          = "completion __complete --"
		activeHelpEnvvar = "_activeHelp_" // FIXME(icio) what should this be?
	)

	nameForVar := root.Name
	nameForVar = strings.ReplaceAll(nameForVar, "-", "_")
	nameForVar = strings.ReplaceAll(nameForVar, ":", "_")

	return []*ffcli.Command{
		{
			Name:       "bash",
			ShortHelp:  "Generate bash shell completion script.",
			ShortUsage: ". <( " + root.Name + " completion bash )",
			UsageFunc:  usageFunc,
			Exec: func(ctx context.Context, args []string) error {
				_, err := fmt.Fprintf(
					os.Stdout, cobra.BashTemplate,
					root.Name, compCmd,
					cobra.ShellCompDirectiveError, cobra.ShellCompDirectiveNoSpace, cobra.ShellCompDirectiveNoFileComp,
					cobra.ShellCompDirectiveFilterFileExt, cobra.ShellCompDirectiveFilterDirs, cobra.ShellCompDirectiveKeepOrder,
					activeHelpEnvvar,
				)
				return err
			},
		},
		{
			Name:       "zsh",
			ShortHelp:  "Generate zsh shell completion script.",
			ShortUsage: ". <( " + root.Name + " completion zsh )",
			UsageFunc:  usageFunc,
			Exec: func(ctx context.Context, args []string) error {
				_, err := fmt.Fprintf(
					os.Stdout, cobra.ZshTemplate,
					root.Name, compCmd,
					cobra.ShellCompDirectiveError, cobra.ShellCompDirectiveNoSpace, cobra.ShellCompDirectiveNoFileComp,
					cobra.ShellCompDirectiveFilterFileExt, cobra.ShellCompDirectiveFilterDirs, cobra.ShellCompDirectiveKeepOrder,
					activeHelpEnvvar,
				)
				return err
			},
		},
		{
			Name:       "fish",
			ShortHelp:  "Generate fish shell completion script.",
			ShortUsage: root.Name + " completion fish | source",
			UsageFunc:  usageFunc,
			Exec: func(ctx context.Context, args []string) error {
				_, err := fmt.Fprintf(
					os.Stdout, cobra.FishTemplate,
					nameForVar, root.Name, compCmd,
					cobra.ShellCompDirectiveError, cobra.ShellCompDirectiveNoSpace, cobra.ShellCompDirectiveNoFileComp,
					cobra.ShellCompDirectiveFilterFileExt, cobra.ShellCompDirectiveFilterDirs, cobra.ShellCompDirectiveKeepOrder, activeHelpEnvvar,
				)
				return err
			},
		},
		{
			Name:       "powershell",
			ShortHelp:  "Generate powershell completion script.",
			ShortUsage: root.Name + " completion powershell | Out-String | Invoke-Expression",
			UsageFunc:  usageFunc,
			Exec: func(ctx context.Context, args []string) error {
				_, err := fmt.Fprintf(
					os.Stdout, cobra.PowershellTemplate,
					root.Name, nameForVar, compCmd,
					cobra.ShellCompDirectiveError, cobra.ShellCompDirectiveNoSpace, cobra.ShellCompDirectiveNoFileComp,
					cobra.ShellCompDirectiveFilterFileExt, cobra.ShellCompDirectiveFilterDirs, cobra.ShellCompDirectiveKeepOrder,
					activeHelpEnvvar,
				)
				return err
			},
		},
	}
}
