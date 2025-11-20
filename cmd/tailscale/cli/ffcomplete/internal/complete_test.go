// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package internal_test

import (
	_ "embed"
	"flag"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/cmd/tailscale/cli/ffcomplete/internal"
)

func newFlagSet(name string, errh flag.ErrorHandling, flags func(fs *flag.FlagSet)) *flag.FlagSet {
	fs := flag.NewFlagSet(name, errh)
	if flags != nil {
		flags(fs)
	}
	return fs
}

func TestComplete(t *testing.T) {
	t.Parallel()

	// Build our test program in testdata.
	root := &ffcli.Command{
		Name: "prog",
		FlagSet: newFlagSet("prog", flag.ContinueOnError, func(fs *flag.FlagSet) {
			fs.Bool("v", false, "verbose")
			fs.Bool("root-bool", false, "root `bool`")
			fs.String("root-str", "", "some `text`")
		}),
		Subcommands: []*ffcli.Command{
			{
				Name:      "debug",
				ShortHelp: "Debug data",
				FlagSet: newFlagSet("prog debug", flag.ExitOnError, func(fs *flag.FlagSet) {
					fs.String("cpu-profile", "", "write cpu profile to `file`")
					fs.Bool("debug-bool", false, "debug bool")
					fs.Int("level", 0, "a number")
					fs.String("enum", "", "a flag that takes several specific values")
					ffcomplete.Flag(fs, "enum", ffcomplete.Fixed("alpha", "beta", "charlie"))
				}),
			},
			func() *ffcli.Command {
				cmd := &ffcli.Command{
					Name: "ping",
					FlagSet: newFlagSet("prog ping", flag.ContinueOnError, func(fs *flag.FlagSet) {
						fs.String("until", "", "when pinging should end\nline break!")
						ffcomplete.Flag(fs, "until", ffcomplete.Fixed("forever", "direct"))
					}),
				}
				ffcomplete.Args(cmd, ffcomplete.Fixed(
					"jupiter\t5th planet\nand largets",
					"neptune\t8th planet",
					"venus\t2nd planet",
					"\tonly description",
					"\nonly line break",
				))
				return cmd
			}(),
		},
	}

	tests := []struct {
		args      []string
		showFlags bool
		showDescs bool
		wantComp  []string
		wantDir   ffcomplete.ShellCompDirective
	}{
		{
			args:     []string{"deb"},
			wantComp: []string{"debug"},
		},
		{
			args:      []string{"deb"},
			showDescs: true,
			wantComp:  []string{"debug\tDebug data"},
		},
		{
			args:     []string{"-"},
			wantComp: []string{"--root-bool", "--root-str", "-v"},
		},
		{
			args:     []string{"--"},
			wantComp: []string{"--root-bool", "--root-str", "--v"},
		},
		{
			args:     []string{"-r"},
			wantComp: []string{"-root-bool", "-root-str"},
		},
		{
			args:     []string{"--r"},
			wantComp: []string{"--root-bool", "--root-str"},
		},
		{
			args:     []string{"--root-str=s", "--r"},
			wantComp: []string{"--root-bool"}, // omits --root-str which is already set
		},
		{
			// '--' disables flag parsing, so we shouldn't suggest flags.
			args:     []string{"--", "--root"},
			wantComp: nil,
		},
		{
			// '--' is used as the value of '--root-str'.
			args:     []string{"--root-str", "--", "--r"},
			wantComp: []string{"--root-bool"},
		},
		{
			// '--' here is a flag value, so doesn't disable flag parsing.
			args:     []string{"--root-str", "--", "--root"},
			wantComp: []string{"--root-bool"},
		},
		{
			// Equivalent to '--root-str=-- -- --r' meaning '--r' is not
			// a flag because it's preceded by a '--' argument:
			// https://go.dev/play/p/UCtftQqVhOD.
			args:     []string{"--root-str", "--", "--", "--r"},
			wantComp: nil,
		},
		{
			args:     []string{"--root-bool="},
			wantComp: []string{"true", "false"},
		},
		{
			args:     []string{"--root-bool=t"},
			wantComp: []string{"true"},
		},
		{
			args:     []string{"--root-bool=T"},
			wantComp: []string{"TRUE"},
		},
		{
			args:     []string{"debug", "--de"},
			wantComp: []string{"--debug-bool"},
		},
		{
			args:     []string{"debug", "--enum="},
			wantComp: []string{"alpha", "beta", "charlie"},
			wantDir:  ffcomplete.ShellCompDirectiveNoFileComp,
		},
		{
			args:     []string{"debug", "--enum=al"},
			wantComp: []string{"alpha"},
			wantDir:  ffcomplete.ShellCompDirectiveNoFileComp,
		},
		{
			args:     []string{"debug", "--level", ""},
			wantComp: nil,
		},
		{
			args:     []string{"debug", "--enum", "b"},
			wantComp: []string{"beta"},
			wantDir:  ffcomplete.ShellCompDirectiveNoFileComp,
		},
		{
			args:     []string{"debug", "--enum", "al"},
			wantComp: []string{"alpha"},
			wantDir:  ffcomplete.ShellCompDirectiveNoFileComp,
		},
		{
			args:      []string{"ping", ""},
			showFlags: true,
			wantComp:  []string{"--until", "jupiter", "neptune", "venus"},
			wantDir:   ffcomplete.ShellCompDirectiveNoFileComp,
		},
		{
			args:      []string{"ping", ""},
			showFlags: true,
			showDescs: true,
			wantComp: []string{
				"--until\twhen pinging should end",
				"jupiter\t5th planet",
				"neptune\t8th planet",
				"venus\t2nd planet",
			},
			wantDir: ffcomplete.ShellCompDirectiveNoFileComp,
		},
		{
			args:     []string{"ping", ""},
			wantComp: []string{"jupiter", "neptune", "venus"},
			wantDir:  ffcomplete.ShellCompDirectiveNoFileComp,
		},
		{
			args:     []string{"ping", "j"},
			wantComp: []string{"jupiter"},
			wantDir:  ffcomplete.ShellCompDirectiveNoFileComp,
		},
	}

	// Run the tests.
	for _, test := range tests {
		name := strings.Join(test.args, "␣")
		if test.showFlags {
			name += "+flags"
		}
		if test.showDescs {
			name += "+descs"
		}
		t.Run(name, func(t *testing.T) {
			// Capture the binary
			complete, dir, err := internal.Complete(root, test.args, test.showFlags, test.showDescs)
			if err != nil {
				t.Fatalf("completion error: %s", err)
			}

			// Test the results match our expectation.
			if test.wantComp != nil {
				if diff := cmp.Diff(test.wantComp, complete); diff != "" {
					t.Errorf("unexpected completion directives (-want +got):\n%s", diff)
				}
			}
			if test.wantDir != dir {
				t.Errorf("got shell completion directive %[1]d (%[1]s), want %[2]d (%[2]s)", dir, test.wantDir)
			}
		})
	}
}
