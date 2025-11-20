// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale/apitype"
)

var logoutArgs struct {
	reason string
}

var logoutCmd = &ffcli.Command{
	Name:       "logout",
	ShortUsage: "tailscale logout",
	ShortHelp:  "Disconnect from Tailscale and expire current node key",

	LongHelp: strings.TrimSpace(`
"tailscale logout" brings the network down and invalidates
the current node key, forcing a future use of it to cause
a reauthentication.
`),
	Exec: runLogout,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("logout")
		fs.StringVar(&logoutArgs.reason, "reason", "", "reason for the logout, if required by a policy")
		return fs
	})(),
}

func runLogout(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("too many non-flag arguments: %q", args)
	}
	ctx = apitype.RequestReasonKey.WithValue(ctx, logoutArgs.reason)
	return localClient.Logout(ctx)
}
