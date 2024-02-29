// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19 && ts_omit_completion

package ffcomplete

import (
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func Inject(root *ffcli.Command, hide func(*ffcli.Command), usageFunc func(*ffcli.Command) string) {}

func Flag(fs *flag.FlagSet, name string, comp CompleteFunc)     {}
func Args(cmd *ffcli.Command, comp CompleteFunc) *ffcli.Command { return cmd }
