// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"flag"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var (
	maybeJetKVMConfigureCmd,
	maybeConfigSynologyCertCmd,
	_ func() *ffcli.Command // non-nil only on Linux/arm for JetKVM
)

func configureCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "configure",
		ShortUsage: "tailscale configure <subcommand>",
		ShortHelp:  "Configure the host to enable more Tailscale features",
		LongHelp: strings.TrimSpace(`
The 'configure' set of commands are intended to provide a way to enable different
services on the host to use Tailscale in more ways.
`),
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("configure")
			return fs
		})(),
		Subcommands: nonNilCmds(
			configureKubeconfigCmd(),
			synologyConfigureCmd(),
			ccall(maybeConfigSynologyCertCmd),
			ccall(maybeSysExtCmd),
			ccall(maybeVPNConfigCmd),
			ccall(maybeJetKVMConfigureCmd),
			ccall(maybeSystrayCmd),
		),
	}
}

// ccall calls the function f if it is non-nil, and returns its result.
//
// It returns the zero value of the type T if f is nil.
func ccall[T any](f func() T) T {
	var zero T
	if f == nil {
		return zero
	}
	return f()
}
