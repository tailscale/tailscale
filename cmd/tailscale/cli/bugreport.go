// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
)

var bugReportCmd = &ffcli.Command{
	Name:       "bugreport",
	Exec:       runBugReport,
	ShortHelp:  "Print a shareable identifier to help diagnose issues",
	ShortUsage: "tailscale bugreport [note]",
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
	opts := local.BugReportOpts{
		Note:     note,
		Diagnose: bugReportArgs.diagnose,
	}
	if !bugReportArgs.record {
		// Simple, non-record case
		logMarker, err := localClient.BugReportWithOpts(ctx, opts)
		if err != nil {
			return err
		}
		outln(logMarker)
		return nil
	}

	// Recording; run the request in the background
	done := make(chan struct{})
	opts.Record = done

	type bugReportResp struct {
		marker string
		err    error
	}
	resCh := make(chan bugReportResp, 1)
	go func() {
		m, err := localClient.BugReportWithOpts(ctx, opts)
		resCh <- bugReportResp{m, err}
	}()

	outln("Recording started; please reproduce your issue and then press Enter...")
	fmt.Scanln()
	close(done)
	res := <-resCh

	if res.err != nil {
		return res.err
	}

	outln(res.marker)
	outln("Please provide both bugreport markers above to the support team or GitHub issue.")
	return nil
}
