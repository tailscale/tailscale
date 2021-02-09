// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package block TODO TODO TODO.
package block

// Next steps:
//  * refactor out chunk selection, with tests.
//  * support AllowNextLine
//  * add docs

import (
	"bytes"
	"runtime"
	"strconv"
	"time"

	"tailscale.com/types/logger"
)

func Watch(maxMinutes int, logf logger.Logf) {
	buf := make([]byte, 4096)
	for {
		time.Sleep(time.Duration(maxMinutes) * time.Minute)

		// Read all goroutine stacks.
		// It'd be nicer to use pprof.Lookup("goroutine"),
		// but it doesn't have the per-goroutine header that includes
		// how long that goroutine has been blocked.
		for {
			n := runtime.Stack(buf, true)
			if n < len(buf) {
				buf = buf[:n]
				break
			}
			buf = buf[:cap(buf)]
			buf = append(buf, 0)
		}

		// Parse the goroutine stacks, looking for goroutines that have been blocked for a long time.
		// This is best-effort; the formatting that the runtime uses can change.
		// See runtime.goroutineheader for the code that writes the header.

		// Stacks come in goroutine chunks separated by blank lines.
		chunks := bytes.Split(buf, doubleNewline)

		// Check each goroutine to see whether it is over the time limit.
		for _, chunk := range chunks {
			minutes, ok := goroutineMinutesBlocked(chunk)
			if !ok {
				continue
			}
			if minutes > maxMinutes {
				// Dump all stacks.
				logf("detected goroutines blocked > %d minutes\n%q", maxMinutes, buf)
				break
			}
		}
	}
}

func AllowNextLine() {

}

func AllowLine() {

}

var (
	doubleNewline = []byte("\n\n")
	goroutine     = []byte("goroutine ")
	commaSpace    = []byte(", ")
	spaceMinutes  = []byte(" minutes")
)

// goroutineMinutesBlocked reports the number of minutes the goroutine
// whose stack is in buf was blocked for (and whether the parse succeeded).
func goroutineMinutesBlocked(stack []byte) (minutes int, ok bool) {
	// Each chunk begins like
	//   goroutine 0 [idle]:
	// or
	//   goroutine 1 [chan receive, 9 minutes]:
	// We only care about lines that have a minutes count.
	if !bytes.HasPrefix(stack, goroutine) {
		return 0, false
	}
	// Extract first line.
	i := bytes.IndexByte(stack, '\n')
	if i < 0 {
		return 0, false
	}
	stack = stack[:i]
	// Find the part between the comma and the m.
	i = bytes.Index(stack, commaSpace)
	if i < 0 {
		return 0, false
	}
	stack = stack[i+len(commaSpace):]
	i = bytes.Index(stack, spaceMinutes)
	if i < 0 {
		return 0, false
	}
	stack = stack[:i]
	// Attempt to decode the number of minutes.
	minutes, err := strconv.Atoi(string(stack))
	if err != nil {
		return 0, false
	}
	return minutes, true
}
