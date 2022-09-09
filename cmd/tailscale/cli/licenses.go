// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"runtime"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var licensesCmd = &ffcli.Command{
	Name:       "licenses",
	ShortUsage: "licenses",
	ShortHelp:  "Get open source license information",
	LongHelp:   "Get open source license information",
	Exec:       runLicenses,
}

// licensesURL returns the absolute URL containing open source license information for the current platform.
func licensesURL() string {
	switch runtime.GOOS {
	case "android":
		return "https://tailscale.com/licenses/android"
	case "darwin", "ios":
		return "https://tailscale.com/licenses/apple"
	case "windows":
		return "https://tailscale.com/licenses/windows"
	default:
		return "https://tailscale.com/licenses/tailscale"
	}
}

func runLicenses(ctx context.Context, args []string) error {
	licenses := licensesURL()
	outln(`
Tailscale wouldn't be possible without the contributions of thousands of open
source developers. To see the open source packages included in Tailscale and
their respective license information, visit:

    ` + licenses)
	return nil
}
