// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || ts_omit_systray

package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
)

// TODO(will): update URL to KB article when available
var systrayHelp = strings.TrimSpace(`
The Tailscale systray app is not included in this client build.
To run it manually, see https://github.com/tailscale/tailscale/tree/main/cmd/systray
`)

var systrayCmd = &ffcli.Command{
	Name:       "systray",
	ShortUsage: "tailscale systray",
	ShortHelp:  "Not available in this client build",
	LongHelp:   hidden + systrayHelp,
	Exec: func(_ context.Context, _ []string) error {
		fmt.Println(systrayHelp)
		return nil
	},
}
