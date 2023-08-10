// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kernellog

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
)

var lineRegexp = regexp.MustCompile(`\A\<(\d+)\>\[( *\d+\.\d+)\](.*)\z`)

func (Check) Run(_ context.Context, logf logger.Logf) error {
	var (
		conntrackFull int
	)
	invalid, err := iterateKernelLog(func(level int, ts float64, text string) bool {
		if strings.Contains(text, "nf_conntrack: table full, dropping packet") {
			conntrackFull++
		}
		return true
	})

	if invalid > 0 {
		logf("invalid log lines: %d", invalid)
	}
	if conntrackFull > 0 {
		logf("nf_conntrack table full lines: %d", conntrackFull)
	}
	return err
}

func iterateKernelLog(cb func(int, float64, string) bool) (invalid int, err error) {
	buf, err := readLogBuffer()
	if err != nil {
		return invalid, err
	}

	// Parse the logs
	scanner := bufio.NewScanner(bytes.NewReader(buf))
	for scanner.Scan() {
		// Line format:
		//    <3>[29037.645184] Message text goes here
		//    xxx yyyyyyyyyyyy  zzzzzzzzzzzzzzzzzzzzzz
		//     |       |                   |
		//     level   |                   |
		//       time since boot           |
		//                          message string
		matches := lineRegexp.FindStringSubmatch(scanner.Text())
		if matches == nil {
			invalid++
			continue
		}

		level, err := strconv.Atoi(matches[1])
		if err != nil {
			invalid++
			continue
		}

		// Convert the timestamp to a number
		timestamp, err := strconv.ParseFloat(strings.TrimSpace(matches[2]), 64)
		if err != nil {
			invalid++
			continue
		}

		// Don't require a space prefix, but if there is one, remove
		// it. Multiple spaces might be intentional and thus should be
		// preserved.
		text := matches[3]
		if text[0] == ' ' {
			text = text[1:]
		}

		if !cb(level, timestamp, text) {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return invalid, err
	}
	return invalid, nil
}

func readLogBuffer() ([]byte, error) {
	// Get the size of the kernel log buffer
	sz, err := unix.Klogctl(unix.SYSLOG_ACTION_SIZE_BUFFER, nil)
	if err != nil {
		return nil, fmt.Errorf("getting kernel log buffer size: %w", err)
	}

	// Allocate a buffer and read the whole thing
	buf := make([]byte, sz)
	n, err := unix.Klogctl(unix.SYSLOG_ACTION_READ_ALL, buf)
	if err != nil {
		return nil, fmt.Errorf("reading kernel log buffer: %w", err)
	}
	return buf[:n], nil
}
