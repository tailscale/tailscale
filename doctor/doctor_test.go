// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package doctor

import (
	"context"
	"fmt"
	"sync"
	"testing"

	qt "github.com/frankban/quicktest"
	"tailscale.com/types/logger"
)

func TestRunChecks(t *testing.T) {
	c := qt.New(t)
	var (
		mu    sync.Mutex
		lines []string
	)
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}

	ctx := context.Background()
	RunChecks(ctx, logf,
		testCheck1{},
		CheckFunc("testcheck2", func(_ context.Context, log logger.Logf) error {
			log("check 2")
			return nil
		}),
	)

	mu.Lock()
	defer mu.Unlock()
	c.Assert(lines, qt.Contains, "testcheck1: check 1")
	c.Assert(lines, qt.Contains, "testcheck2: check 2")
}

type testCheck1 struct{}

func (t testCheck1) Name() string { return "testcheck1" }
func (t testCheck1) Run(_ context.Context, log logger.Logf) error {
	log("check 1")
	return nil
}
