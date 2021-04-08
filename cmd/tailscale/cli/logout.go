// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"log"
	"strings"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/client/tailscale"
)

var logoutCmd = &ffcli.Command{
	Name:       "logout",
	ShortUsage: "logout [flags]",
	ShortHelp:  "down + expire current node key",

	LongHelp: strings.TrimSpace(`
"tailscale logout" brings the network down and invalidates
the current node key, forcing a future use of it to cause
a reauthentication.
`),
	Exec: runLogout,
}

func runLogout(ctx context.Context, args []string) error {
	if len(args) > 0 {
		log.Fatalf("too many non-flag arguments: %q", args)
	}
	return tailscale.Logout(ctx)
}
