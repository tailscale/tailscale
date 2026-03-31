// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !ts_omit_cachenetmap

package cli

import (
	"context"
	"errors"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func init() {
	debugClearNetmapCacheCmd = func() *ffcli.Command {
		return &ffcli.Command{
			Name:       "clear-netmap-cache",
			ShortUsage: "tailscale debug clear-netmap-cache",
			ShortHelp:  "Remove and discard cached network maps (if any)",
			Exec:       runDebugClearNetmapCache,
		}
	}
}

func runDebugClearNetmapCache(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("unexpected arguments")
	}
	return localClient.DebugAction(ctx, "clear-netmap-cache")
}
