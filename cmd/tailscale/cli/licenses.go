// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/licenses"
)

var licensesCmd = &ffcli.Command{
	Name:       "licenses",
	ShortUsage: "tailscale licenses",
	ShortHelp:  "Get open source license information",
	LongHelp:   "Get open source license information",
	Exec:       runLicenses,
}

func runLicenses(ctx context.Context, args []string) error {
	url := licenses.LicensesURL()
	outln(`
Tailscale wouldn't be possible without the contributions of thousands of open
source developers. To see the open source packages included in Tailscale and
their respective license information, visit:

    ` + url)
	return nil
}
