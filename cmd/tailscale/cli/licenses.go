// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var licensesCmd = &ffcli.Command{
	Name:       "licenses",
	ShortUsage: "licenses",
	ShortHelp:  "Get open source license information",
	LongHelp:   "Get open source license information",
	Exec:       runLicenses,
}

func runLicenses(ctx context.Context, args []string) error {
	outln(`
Tailscale wouldn't be possible without the contributions of thousands of open
source developers. To see the open source packages included in Tailscale and
their respective license information, visit:

    https://tailscale.com/licenses/tailscale`)
	return nil
}
