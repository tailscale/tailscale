// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19 && !ts_omit_completion && !ts_omit_completion_scripts

package ffcomplete

import (
	"context"
	"flag"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/tempfork/spf13/cobra"
)

func compCmd(fs *flag.FlagSet) string {
	var s strings.Builder
	s.WriteString("completion __complete")
	fs.VisitAll(func(f *flag.Flag) {
		s.WriteString(" --")
		s.WriteString(f.Name)
		s.WriteString("=")
		s.WriteString(f.Value.String())
	})
	s.WriteString(" --")
	return s.String()
}

func scriptCmds(root *ffcli.Command, usageFunc func(*ffcli.Command) string) []*ffcli.Command {
	nameForVar := root.Name
	nameForVar = strings.ReplaceAll(nameForVar, "-", "_")
	nameForVar = strings.ReplaceAll(nameForVar, ":", "_")

	var (
		bashFS = newFS("bash", &compOpts{})
		zshFS  = newFS("zsh", &compOpts{})
		fishFS = newFS("fish", &compOpts{})
		pwshFS = newFS("powershell", &compOpts{})
	)

	return []*ffcli.Command{
		{
			Name:       "bash",
			ShortHelp:  "Generate bash shell completion script",
			ShortUsage: ". <( " + root.Name + " completion bash )",
			UsageFunc:  usageFunc,
			FlagSet:    bashFS,
			Exec: func(ctx context.Context, args []string) error {
				return cobra.ScriptBash(os.Stdout, root.Name, compCmd(bashFS), nameForVar)
			},
		},
		{
			Name:       "zsh",
			ShortHelp:  "Generate zsh shell completion script",
			ShortUsage: ". <( " + root.Name + " completion zsh )",
			UsageFunc:  usageFunc,
			FlagSet:    zshFS,
			Exec: func(ctx context.Context, args []string) error {
				return cobra.ScriptZsh(os.Stdout, root.Name, compCmd(zshFS), nameForVar)
			},
		},
		{
			Name:       "fish",
			ShortHelp:  "Generate fish shell completion script",
			ShortUsage: root.Name + " completion fish | source",
			UsageFunc:  usageFunc,
			FlagSet:    fishFS,
			Exec: func(ctx context.Context, args []string) error {
				return cobra.ScriptFish(os.Stdout, root.Name, compCmd(fishFS), nameForVar)
			},
		},
		{
			Name:       "powershell",
			ShortHelp:  "Generate powershell completion script",
			ShortUsage: root.Name + " completion powershell | Out-String | Invoke-Expression",
			UsageFunc:  usageFunc,
			FlagSet:    pwshFS,
			Exec: func(ctx context.Context, args []string) error {
				return cobra.ScriptPowershell(os.Stdout, root.Name, compCmd(pwshFS), nameForVar)
			},
		},
	}
}
