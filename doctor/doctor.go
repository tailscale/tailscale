// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package doctor contains more in-depth healthchecks that can be run to aid in
// diagnosing Tailscale issues.
package doctor

import (
	"context"
	"sync"

	"tailscale.com/types/logger"
)

// Check is the interface defining a singular check.
//
// A check should log information that it gathers using the provided log
// function, and should attempt to make as much progress as possible in error
// conditions.
type Check interface {
	// Name should return a name describing this check, in lower-kebab-case
	// (i.e. "my-check", not "MyCheck" or "my_check").
	Name() string
	// Run executes the check, logging diagnostic information to the
	// provided logger function.
	Run(context.Context, logger.Logf) error
}

// RunChecks runs a list of checks in parallel, and logs any returned errors
// after all checks have returned.
func RunChecks(ctx context.Context, logf logger.Logf, checks ...Check) {
	if len(checks) == 0 {
		return
	}

	type logRecord struct {
		format string
		args   []any
	}

	var (
		wg       sync.WaitGroup
		outputMu sync.Mutex // protecting logf
	)
	wg.Add(len(checks))
	for _, check := range checks {
		go func(c Check) {
			defer wg.Done()

			// Log everything in a batch at the end of the function
			// so that we don't interleave messages.
			var (
				logMu sync.Mutex // protects logs; acquire before outputMu
				logs  []logRecord
			)
			checkLogf := func(format string, args ...any) {
				logMu.Lock()
				defer logMu.Unlock()
				logs = append(logs, logRecord{format, args})
			}
			defer func() {
				logMu.Lock()
				defer logMu.Unlock()
				outputMu.Lock()
				defer outputMu.Unlock()

				name := c.Name()
				for _, log := range logs {
					logf(name+": "+log.format, log.args...)
				}
			}()

			if err := c.Run(ctx, checkLogf); err != nil {
				checkLogf("error: %v", err)
			}
		}(check)
	}
	wg.Wait()
}

// CheckFunc creates a Check from a name and a function.
func CheckFunc(name string, run func(context.Context, logger.Logf) error) Check {
	return checkFunc{name, run}
}

type checkFunc struct {
	name string
	run  func(context.Context, logger.Logf) error
}

func (c checkFunc) Name() string                                   { return c.name }
func (c checkFunc) Run(ctx context.Context, log logger.Logf) error { return c.run(ctx, log) }
