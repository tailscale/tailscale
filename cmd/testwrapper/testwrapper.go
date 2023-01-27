// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// testwrapper is a wrapper for retrying flaky tests, using the -exec flag of
// 'go test'. Tests that are flaky can use the 'flakytest' subpackage to mark
// themselves as flaky and be retried on failure.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
)

const (
	retryStatus   = 123
	maxIterations = 3
)

func main() {
	ctx := context.Background()
	debug := os.Getenv("TS_TESTWRAPPER_DEBUG") != ""

	log.SetPrefix("testwrapper: ")
	if !debug {
		log.SetFlags(0)
	}

	for i := 1; i <= maxIterations; i++ {
		if i > 1 {
			log.Printf("retrying flaky tests (%d of %d)", i, maxIterations)
		}
		cmd := exec.CommandContext(ctx, os.Args[1], os.Args[2:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(), "TS_IN_TESTWRAPPER=1")
		err := cmd.Run()
		if err == nil {
			return
		}

		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			if debug {
				log.Printf("error isn't an ExitError")
			}
			os.Exit(1)
		}

		if code := exitErr.ExitCode(); code != retryStatus {
			if debug {
				log.Printf("code (%d) != retryStatus (%d)", code, retryStatus)
			}
			os.Exit(code)
		}
	}

	log.Printf("test did not pass in %d iterations", maxIterations)
	os.Exit(1)
}
