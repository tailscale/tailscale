// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var logoutCmd = &ffcli.Command{
	Name:       "logout",
	ShortUsage: "logout [flags]",
	ShortHelp:  "Disconnect from Tailscale and expire current node key",

	LongHelp: strings.TrimSpace(`
"tailscale logout" brings the network down and invalidates
the current node key, forcing a future use of it to cause
a reauthentication.
`),
	Exec: runLogout,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("logout")
		fs.BoolVar(&logoutArgs.async, "async", false, "Does not wait for logout to be complete (status can be queried to determine success)")
		return fs
	})(),
}

var logoutArgs struct {
	async bool
}

func runLogout(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("too many non-flag arguments: %q", args)
	}
	if logoutArgs.async {
		return localClient.LogoutAsync(ctx)
	}
	return localClient.Logout(ctx)
}
