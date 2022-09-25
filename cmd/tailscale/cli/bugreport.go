// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var bugReportCmd = &ffcli.Command{
	Name:       "bugreport",
	Exec:       runBugReport,
	ShortHelp:  "Print a shareable identifier to help diagnose issues",
	ShortUsage: "bugreport [note]",
}

func runBugReport(ctx context.Context, args []string) error {
	var note string
	switch len(args) {
	case 0:
	case 1:
		note = args[0]
	default:
		return errors.New("unknown arguments")
	}
	logMarker, err := localClient.BugReport(ctx, note)
	if err != nil {
		return err
	}
	outln(logMarker)
	return nil
}
