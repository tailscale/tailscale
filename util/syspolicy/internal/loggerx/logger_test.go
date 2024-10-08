// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package loggerx

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"tailscale.com/types/logger"
)

func TestDebugLogging(t *testing.T) {
	var normal, verbose strings.Builder
	SetForTest(t, logfTo(&normal), logfTo(&verbose))

	checkOutput := func(wantNormal, wantVerbose string) {
		t.Helper()
		if gotNormal := normal.String(); gotNormal != wantNormal {
			t.Errorf("Unexpected normal output: got %q; want %q", gotNormal, wantNormal)
		}
		if gotVerbose := verbose.String(); gotVerbose != wantVerbose {
			t.Errorf("Unexpected verbose output: got %q; want %q", gotVerbose, wantVerbose)
		}
		normal.Reset()
		verbose.Reset()
	}

	Errorf("This is an error message: %v", 42)
	checkOutput("This is an error message: 42", "")
	Verbosef("This is a verbose message: %v", 17)
	checkOutput("", "This is a verbose message: 17")

	SetDebugLoggingEnabled(true)
	Errorf("This is an error message: %v", 42)
	checkOutput("This is an error message: 42", "")
	Verbosef("This is a verbose message: %v", 17)
	checkOutput("This is a verbose message: 17", "")

	SetDebugLoggingEnabled(false)
	Errorf("This is an error message: %v", 42)
	checkOutput("This is an error message: 42", "")
	Verbosef("This is a verbose message: %v", 17)
	checkOutput("", "This is a verbose message: 17")
}

func logfTo(w io.Writer) logger.Logf {
	return func(format string, args ...any) {
		fmt.Fprintf(w, format, args...)
	}
}
