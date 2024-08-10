// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package internal contains internal code for the ffcomplete package.
package internal

import (
	"flag"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/tempfork/spf13/cobra"
)

var (
	CompleteCmds  map[*ffcli.Command]CompleteFunc
	CompleteFlags map[*flag.Flag]CompleteFunc
)

type CompleteFunc func([]string) ([]string, cobra.ShellCompDirective, error)

// Complete returns the autocomplete suggestions for the root program and args.
//
// The returned words do not necessarily need to be prefixed with the last arg
// which is being completed. For example, '--bool-flag=' will have completions
// 'true' and 'false'.
//
// "HIDDEN: " is trimmed from the start of Flag Usage's.
func Complete(root *ffcli.Command, args []string, startFlags, descs bool) (words []string, dir cobra.ShellCompDirective, err error) {
	// Explicitly log panics.
	defer func() {
		if r := recover(); r != nil {
			if rerr, ok := err.(error); ok {
				err = fmt.Errorf("panic: %w", rerr)
			} else {
				err = fmt.Errorf("panic: %v", r)
			}
		}
	}()

	// Set up the arguments.
	if len(args) == 0 {
		args = []string{""}
	}

	// Completion criteria.
	completeArg := args[len(args)-1]
	args = args[:len(args)-1]
	emitFlag := startFlags || strings.HasPrefix(completeArg, "-")
	emitArgs := true

	// Traverse the command-tree to find the cmd command whose
	// subcommand, flags, or arguments are being completed.
	cmd := root
walk:
	for {
		// Ensure there's a flagset with ContinueOnError set.
		if cmd.FlagSet == nil {
			cmd.FlagSet = flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
		}
		cmd.FlagSet.Init(cmd.FlagSet.Name(), flag.ContinueOnError)

		// Manually split the args so we know when we're completing flags/args.
		flagArgs, argArgs, flagNeedingValue := splitFlagArgs(cmd.FlagSet, args)
		if flagNeedingValue != "" {
			completeArg = flagNeedingValue + "=" + completeArg
			emitFlag = true
		}
		args = argArgs

		// Parse the flags.
		err := ff.Parse(cmd.FlagSet, flagArgs, cmd.Options...)
		if err != nil {
			return nil, 0, fmt.Errorf("%s flag parsing: %w", cmd.Name, err)
		}
		if cmd.FlagSet.NArg() > 0 {
			// This shouldn't happen if splitFlagArgs is accurately finding the
			// split between flags and args.
			_ = false
		}
		if len(args) == 0 {
			break
		}

		// Check if the first argument is actually a subcommand.
		for _, sub := range cmd.Subcommands {
			if strings.EqualFold(sub.Name, args[0]) {
				args = args[1:]
				cmd = sub
				continue walk
			}
		}
		break
	}
	if len(args) > 0 {
		emitFlag = false
	}

	// Complete '-flag=...'. If the args ended with '-flag ...' we will have
	// rewritten to '-flag=...' by now.
	if emitFlag && strings.HasPrefix(completeArg, "-") && strings.Contains(completeArg, "=") {
		// Don't complete '-flag' later on as the
		// flag name is terminated by a '='.
		emitFlag = false
		emitArgs = false

		dashFlag, completeVal, _ := strings.Cut(completeArg, "=")
		_, f := cutDash(dashFlag)
		flag := cmd.FlagSet.Lookup(f)
		if flag != nil {
			if comp := CompleteFlags[flag]; comp != nil {
				// Complete custom flag values.
				var err error
				words, dir, err = comp([]string{completeVal})
				if err != nil {
					return nil, 0, fmt.Errorf("completing %s flag %s: %w", cmd.Name, flag.Name, err)
				}
			} else if isBoolFlag(flag) {
				// Complete true/false.
				for _, vals := range [][]string{
					{"true", "TRUE", "True", "1"},
					{"false", "FALSE", "False", "0"},
				} {
					for _, val := range vals {
						if strings.HasPrefix(val, completeVal) {
							words = append(words, val)
							break
						}
					}
				}
			}
		}
	}

	// Complete '-flag...'.
	if emitFlag {
		used := make(map[string]struct{})
		cmd.FlagSet.Visit(func(f *flag.Flag) {
			used[f.Name] = struct{}{}
		})

		cd, cf := cutDash(completeArg)
		cmd.FlagSet.VisitAll(func(f *flag.Flag) {
			if !strings.HasPrefix(f.Name, cf) {
				return
			}
			// Skip flags already set by the user.
			if _, seen := used[f.Name]; seen {
				return
			}
			// Suggest single-dash '-v' for single-char flags and
			// double-dash '--verbose' for longer.
			d := cd
			if (d == "" || d == "-") && cf == "" && len(f.Name) > 1 {
				d = "--"
			}
			if descs {
				_, usage := flag.UnquoteUsage(f)
				usage = strings.TrimPrefix(usage, "HIDDEN: ")
				if usage != "" {
					words = append(words, d+f.Name+"\t"+usage)
					return
				}
			}
			words = append(words, d+f.Name)
		})
	}

	if emitArgs {
		// Complete 'sub...'.
		for _, sub := range cmd.Subcommands {
			if strings.HasPrefix(sub.Name, completeArg) {
				if descs {
					if sub.ShortHelp != "" {
						words = append(words, sub.Name+"\t"+sub.ShortHelp)
						continue
					}
				}
				words = append(words, sub.Name)
			}
		}

		// Complete custom args.
		if comp := CompleteCmds[cmd]; comp != nil {
			w, d, err := comp(append(args, completeArg))
			if err != nil {
				return nil, 0, fmt.Errorf("completing %s args: %w", cmd.Name, err)
			}
			dir = d
			words = append(words, w...)
		}
	}

	// Strip any descriptions if they were suppressed.
	clean := words[:0]
	for _, w := range words {
		if !descs {
			w, _, _ = strings.Cut(w, "\t")
		}
		w = cutAny(w, "\n\r")
		if w == "" || w[0] == '\t' {
			continue
		}
		clean = append(clean, w)
	}
	return clean, dir, nil
}

func cutAny(s, cutset string) string {
	i := strings.IndexAny(s, cutset)
	if i == -1 {
		return s
	}
	return s[:i]
}

// splitFlagArgs separates a list of command-line arguments into arguments
// comprising flags and their values, preceding arguments to be passed to the
// command. This follows the stdlib 'flag' parsing conventions. If the final
// argument is a flag name which takes a value but has no value specified, it is
// omitted from flagArgs and argArgs and instead returned in needValue.
func splitFlagArgs(fs *flag.FlagSet, args []string) (flagArgs, argArgs []string, flagNeedingValue string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return args[:i], args[i+1:], ""
		}

		d, f := cutDash(a)
		if d == "" {
			return args[:i], args[i:], ""
		}
		if strings.Contains(f, "=") {
			continue
		}

		flag := fs.Lookup(f)
		if flag == nil {
			return args[:i], args[i:], ""
		}
		if isBoolFlag(flag) {
			continue
		}

		// Consume an extra argument for the flag value.
		if i == len(args)-1 {
			return args[:i], nil, args[i]
		}
		i++
	}
	return args, nil, ""
}

func cutDash(s string) (dashes, flag string) {
	if strings.HasPrefix(s, "-") {
		if strings.HasPrefix(s[1:], "-") {
			return "--", s[2:]
		}
		return "-", s[1:]
	}
	return "", s
}

func isBoolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface {
		IsBoolFlag() bool
	})
	return ok && bf.IsBoolFlag()
}
