// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale"
)

var bugReportCmd = &ffcli.Command{
	Name:       "bugreport",
	Exec:       runBugReport,
	ShortHelp:  "Print a shareable identifier to help diagnose issues",
	ShortUsage: "bugreport [note]",
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("bugreport")
		fs.BoolVar(&bugReportArgs.diagnose, "diagnose", false, "run additional in-depth checks")
		fs.BoolVar(&bugReportArgs.record, "record", false, "if true, pause and then write another bugreport")
		return fs
	})(),
}

var bugReportArgs struct {
	diagnose bool
	record   bool
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
	logMarker, err := localClient.BugReportWithOpts(ctx, tailscale.BugReportOpts{
		Note:     note,
		Diagnose: bugReportArgs.diagnose,
	})
	if err != nil {
		return err
	}

	if bugReportArgs.record {
		outln("The initial bugreport is below; please reproduce your issue and then press Enter...")
	}

	outln(logMarker)

	if bugReportArgs.record {
		fmt.Scanln()

		logMarker, err := localClient.BugReportWithOpts(ctx, tailscale.BugReportOpts{})
		if err != nil {
			return err
		}
		outln(logMarker)
		outln("Please provide both bugreport markers above to the support team or GitHub issue.")
	}
	return nil
}
