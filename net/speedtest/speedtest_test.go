// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package speedtest

import (
	"flag"
	"net"
	"testing"
	"time"

	"tailscale.com/cmd/testwrapper/flakytest"
)

var manualTest = flag.Bool("do-speedtest", false, "if true, run the speedtest TestDownload test. Otherwise skip it because it's slow and flaky; see https://github.com/tailscale/tailscale/issues/17338")

func TestDownload(t *testing.T) {
	if !*manualTest {
		t.Skip("skipping slow test without --do-speedtest")
	}
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/17338")

	// start a listener and find the port where the server will be listening.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	serverIP := ln.Addr().String()
	t.Log("server IP found:", serverIP)

	type state struct {
		err error
	}
	displayResult := func(t *testing.T, r Result, start time.Time) {
		t.Helper()
		t.Logf("{ Megabytes: %.2f, Start: %.1f, End: %.1f, Total: %t }", r.MegaBytes(), r.IntervalStart.Sub(start).Seconds(), r.IntervalEnd.Sub(start).Seconds(), r.Total)
	}
	stateChan := make(chan state, 1)

	go func() {
		err := Serve(ln)
		stateChan <- state{err: err}
	}()

	// ensure that the test returns an appropriate number of Result structs
	expectedLen := int(DefaultDuration.Seconds()) + 1

	t.Run("download test", func(t *testing.T) {
		// conduct a download test
		results, err := RunClient(Download, DefaultDuration, serverIP)

		if err != nil {
			t.Fatal("download test failed:", err)
		}

		if len(results) < expectedLen {
			t.Fatalf("download results: expected length: %d, actual length: %d", expectedLen, len(results))
		}

		start := results[0].IntervalStart
		for _, result := range results {
			displayResult(t, result, start)
		}
	})

	t.Run("upload test", func(t *testing.T) {
		// conduct an upload test
		results, err := RunClient(Upload, DefaultDuration, serverIP)

		if err != nil {
			t.Fatal("upload test failed:", err)
		}

		if len(results) < expectedLen {
			t.Fatalf("upload results: expected length: %d, actual length: %d", expectedLen, len(results))
		}

		start := results[0].IntervalStart
		for _, result := range results {
			displayResult(t, result, start)
		}
	})

	// causes the server goroutine to finish
	ln.Close()

	testState := <-stateChan
	if testState.err != nil {
		t.Error("server error:", err)
	}
}
