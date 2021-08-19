// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Program speedtest provides the speedtest command. The reason to keep it separate from
// the normal tailscale cli is because it is not yet ready to go in the tailscale binary.
// It will be included in the tailscale cli after it has been added to tailscaled.

// Example usage for client command: go run cmd/speedtest -host 127.0.0.1:20333 -t 5s
// This will connect to the server on 127.0.0.1:20333 and start a 5 second download speedtest.
// Example usage for server command: go run cmd/speedtest -s -host :20333
// This will start a speedtest server on port 20333.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/net/speedtest"
)

// Runs the speedtest command as a commandline program
func main() {
	args := os.Args[1:]
	if err := speedtestCmd.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	err := speedtestCmd.Run(context.Background())
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, speedtestCmd.ShortUsage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

// speedtestCmd is the root command. It runs either the server or client depending on the
// flags passed to it.
var speedtestCmd = &ffcli.Command{
	Name:       "speedtest",
	ShortUsage: "speedtest [-host <host:port>] [-s] [-r] [-t <test duration>]",
	ShortHelp:  "Run a speed test",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("speedtest", flag.ExitOnError)
		fs.StringVar(&speedtestArgs.host, "host", ":20333", "host:port pair to connect to or listen on")
		fs.DurationVar(&speedtestArgs.testDuration, "t", speedtest.DefaultDuration, "duration of the speed test")
		fs.BoolVar(&speedtestArgs.runServer, "s", false, "run a speedtest server")
		fs.BoolVar(&speedtestArgs.reverse, "r", false, "run in reverse mode (server sends, client receives)")
		return fs
	})(),
	Exec: runSpeedtest,
}

var speedtestArgs struct {
	host         string
	testDuration time.Duration
	runServer    bool
	reverse      bool
}

func runSpeedtest(ctx context.Context, args []string) error {

	if _, _, err := net.SplitHostPort(speedtestArgs.host); err != nil {
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) && addrErr.Err == "missing port in address" {
			// if no port is provided, append the default port
			speedtestArgs.host = net.JoinHostPort(speedtestArgs.host, strconv.Itoa(speedtest.DefaultPort))
		}
	}

	if speedtestArgs.runServer {
		listener, err := net.Listen("tcp", speedtestArgs.host)
		if err != nil {
			return err
		}

		fmt.Printf("listening on %v\n", listener.Addr())

		return speedtest.Serve(listener)
	}

	// Ensure the duration is within the allowed range
	if speedtestArgs.testDuration < speedtest.MinDuration || speedtestArgs.testDuration > speedtest.MaxDuration {
		return fmt.Errorf("test duration must be within %v and %v", speedtest.MinDuration, speedtest.MaxDuration)
	}

	dir := speedtest.Download
	if speedtestArgs.reverse {
		dir = speedtest.Upload
	}

	fmt.Printf("Starting a %s test with %s\n", dir, speedtestArgs.host)
	results, err := speedtest.RunClient(dir, speedtestArgs.testDuration, speedtestArgs.host)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 12, 0, 0, ' ', tabwriter.TabIndent)
	fmt.Println("Results:")
	fmt.Fprintln(w, "Interval\t\tTransfer\t\tBandwidth\t\t")
	for _, r := range results {
		if r.Total {
			fmt.Fprintln(w, "-------------------------------------------------------------------------")
		}
		fmt.Fprintf(w, "%.2f-%.2f\tsec\t%.4f\tMBits\t%.4f\tMbits/sec\t\n", r.IntervalStart.Seconds(), r.IntervalEnd.Seconds(), r.MegaBits(), r.MBitsPerSecond())
	}
	w.Flush()
	return nil
}
