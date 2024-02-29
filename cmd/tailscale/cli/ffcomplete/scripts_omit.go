// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19 && !ts_omit_completion && ts_omit_completion_scripts

package ffcomplete

import "github.com/peterbourgon/ff/v3/ffcli"

func scriptCmds(root *ffcli.Command, usageFunc func(*ffcli.Command) string) []*ffcli.Command {
	return nil
}
