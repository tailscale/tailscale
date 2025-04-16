// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstest

import (
	"bytes"
	"runtime"
	"runtime/pprof"
	"slices"
	"strings"
	"testing"
	"time"
)

// ResourceCheck takes a snapshot of the current goroutines and registers a
// cleanup on tb to verify that after the rest, all goroutines created by the
// test go away. (well, at least that the count matches. Maybe in the future it
// can look at specific routines).
//
// It panics if called from a parallel test.
func ResourceCheck(tb testing.TB) {
	tb.Helper()

	// Set an environment variable (anything at all) just for the
	// side effect of tb.Setenv panicking if we're in a parallel test.
	tb.Setenv("TS_CHECKING_RESOURCES", "1")

	startN, startStacks := goroutines()
	tb.Cleanup(func() {
		if tb.Failed() {
			// Test has failed - but this doesn't catch panics due to
			// https://github.com/golang/go/issues/49929.
			return
		}
		// Goroutines might be still exiting.
		for range 300 {
			if runtime.NumGoroutine() <= startN {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		endN, endStacks := goroutines()
		if endN <= startN {
			return
		}

		// Parse and print goroutines.
		start := parseGoroutines(startStacks)
		end := parseGoroutines(endStacks)
		if testing.Verbose() {
			tb.Logf("goroutines start:\n%s", printGoroutines(start))
			tb.Logf("goroutines end:\n%s", printGoroutines(end))
		}

		// Print goroutine diff, omitting tstest.ResourceCheck goroutines.
		self := func(g goroutine) bool { return bytes.Contains(g.stack, []byte("\ttailscale.com/tstest.goroutines+")) }
		start.goroutines = slices.DeleteFunc(start.goroutines, self)
		end.goroutines = slices.DeleteFunc(end.goroutines, self)
		tb.Logf("goroutine diff (-start +end):\n%s", diffGoroutines(start, end))

		// tb.Failed() above won't report on panics, so we shouldn't call Fatal
		// here or we risk suppressing reporting of the panic.
		tb.Errorf("goroutine count: expected %d, got %d\n", startN, endN)
	})
}

func goroutines() (int, []byte) {
	p := pprof.Lookup("goroutine")
	b := new(bytes.Buffer)
	p.WriteTo(b, 1)
	return p.Count(), b.Bytes()
}

// parseGoroutines takes pprof/goroutines?debug=1 -formatted output sorted by
// count, and splits it into a separate list of goroutines with count and stack
// separated.
//
// Example input:
//
//	goroutine profile: total 408
//	48 @ 0x47bc0e 0x136c6b9 0x136c69e 0x136c7ab 0x1379809 0x13797fa 0x483da1
//	#   0x136c6b8   gvisor.dev/gvisor/pkg/sync.Gopark+0x78                  gvisor.dev/gvisor@v0.0.0-20250205023644-9414b50a5633/pkg/sync/runtime_unsafe.go:33
//	#   0x136c69d   gvisor.dev/gvisor/pkg/sleep.(*Sleeper).nextWaker+0x5d           gvisor.dev/gvisor@v0.0.0-20250205023644-9414b50a5633/pkg/sleep/sleep_unsafe.go:210
//	#   0x136c7aa   gvisor.dev/gvisor/pkg/sleep.(*Sleeper).fetch+0x2a           gvisor.dev/gvisor@v0.0.0-20250205023644-9414b50a5633/pkg/sleep/sleep_unsafe.go:257
//	#   0x1379808   gvisor.dev/gvisor/pkg/sleep.(*Sleeper).Fetch+0xa8           gvisor.dev/gvisor@v0.0.0-20250205023644-9414b50a5633/pkg/sleep/sleep_unsafe.go:280
//	#   0x13797f9   gvisor.dev/gvisor/pkg/tcpip/transport/tcp.(*processor).start+0x99   gvisor.dev/gvisor@v0.0.0-20250205023644-9414b50a5633/pkg/tcpip/transport/tcp/dispatcher.go:291
//
//	48 @ 0x47bc0e 0x413705 0x4132b2 0x10fc905 0x483da1
//	#   0x10fc904   github.com/tailscale/wireguard-go/device.(*Device).RoutineDecryption+0x184  github.com/tailscale/wireguard-go@v0.0.0-20250107165329-0b8b35511f19/device/receive.go:245
//
//	48 @ 0x47bc0e 0x413705 0x4132b2 0x10fcd2a 0x483da1
//	#   0x10fcd29   github.com/tailscale/wireguard-go/device.(*Device).RoutineHandshake+0x169   github.com/tailscale/wireguard-go@v0.0.0-20250107165329-0b8b35511f19/device/receive.go:279
//
//	48 @ 0x47bc0e 0x413705 0x4132b2 0x1100ba7 0x483da1
//	#   0x1100ba6   github.com/tailscale/wireguard-go/device.(*Device).RoutineEncryption+0x186  github.com/tailscale/wireguard-go@v0.0.0-20250107165329-0b8b35511f19/device/send.go:451
//
//	26 @ 0x47bc0e 0x458e57 0x847587 0x483da1
//	#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
//
//	13 @ 0x47bc0e 0x458e57 0x754927 0x483da1
//	#   0x754926    net/http.(*persistConn).writeLoop+0xe6  net/http/transport.go:2596
//
//	7 @ 0x47bc0e 0x413705 0x4132b2 0x10fda4d 0x483da1
//	#   0x10fda4c   github.com/tailscale/wireguard-go/device.(*Peer).RoutineSequentialReceiver+0x16c    github.com/tailscale/wireguard-go@v0.0.0-20250107165329-0b8b35511f19/device/receive.go:443
func parseGoroutines(g []byte) goroutineDump {
	head, tail, ok := bytes.Cut(g, []byte("\n"))
	if !ok {
		return goroutineDump{head: head}
	}

	raw := bytes.Split(tail, []byte("\n\n"))
	parsed := make([]goroutine, 0, len(raw))
	for _, s := range raw {
		count, rem, ok := bytes.Cut(s, []byte(" @ "))
		if !ok {
			continue
		}
		header, stack, _ := bytes.Cut(rem, []byte("\n"))
		sort := slices.Clone(header)
		reverseWords(sort)
		parsed = append(parsed, goroutine{count, header, stack, sort})
	}

	return goroutineDump{head, parsed}
}

type goroutineDump struct {
	head       []byte
	goroutines []goroutine
}

// goroutine is a parsed stack trace in pprof goroutine output, e.g.
// "10 @ 0x100 0x001\n# 0x100 test() test.go\n# 0x001 main() test.go".
type goroutine struct {
	count  []byte // e.g. "10"
	header []byte // e.g. "0x100 0x001"
	stack  []byte // e.g. "# 0x100 test() test.go\n# 0x001 main() test.go"

	// sort is the same pointers as in header, but in reverse order so that we
	// can place related goroutines near each other by sorting on this field.
	// E.g. "0x001 0x100".
	sort []byte
}

func (g goroutine) Compare(h goroutine) int {
	return bytes.Compare(g.sort, h.sort)
}

// reverseWords repositions the words in b such that they are reversed.
// Words are separated by spaces. New lines are not considered.
// https://sketch.dev/sk/a4ef
func reverseWords(b []byte) {
	if len(b) == 0 {
		return
	}

	// First, reverse the entire slice.
	reverse(b)

	// Then reverse each word individually.
	start := 0
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] == ' ' {
			reverse(b[start:i])
			start = i + 1
		}
	}
}

// reverse reverses bytes in place
func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// printGoroutines returns a text representation of h, gs equivalent to the
// pprof ?debug=1 input parsed by parseGoroutines, except the goroutines are
// sorted in an order easier for diffing.
func printGoroutines(g goroutineDump) []byte {
	var b bytes.Buffer
	b.Write(g.head)

	slices.SortFunc(g.goroutines, goroutine.Compare)
	for _, g := range g.goroutines {
		b.WriteString("\n\n")
		b.Write(g.count)
		b.WriteString(" @ ")
		b.Write(g.header)
		b.WriteString("\n")
		if len(g.stack) > 0 {
			b.Write(g.stack)
		}
	}

	return b.Bytes()
}

// diffGoroutines returns a diff between goroutines of gx and gy.
// Goroutines present in gx and absent from gy are prefixed with "-".
// Goroutines absent from gx and present in gy are prefixed with "+".
// Goroutines present in both but with different counts only show a prefix on the count line.
func diffGoroutines(x, y goroutineDump) string {
	hx, hy := x.head, y.head
	gx, gy := x.goroutines, y.goroutines
	var b strings.Builder
	if !bytes.Equal(hx, hy) {
		b.WriteString("- ")
		b.Write(hx)
		b.WriteString("\n+ ")
		b.Write(hy)
		b.WriteString("\n")
	}

	slices.SortFunc(gx, goroutine.Compare)
	slices.SortFunc(gy, goroutine.Compare)

	writeHeader := func(prefix string, g goroutine) {
		b.WriteString(prefix)
		b.Write(g.count)
		b.WriteString(" @ ")
		b.Write(g.header)
		b.WriteString("\n")
	}
	writeStack := func(prefix string, g goroutine) {
		s := g.stack
		for {
			var h []byte
			h, s, _ = bytes.Cut(s, []byte("\n"))
			if len(h) == 0 && len(s) == 0 {
				break
			}
			b.WriteString(prefix)
			b.Write(h)
			b.WriteString("\n")
		}
	}

	i, j := 0, 0
	for {
		var d int
		switch {
		case i < len(gx) && j < len(gy):
			d = gx[i].Compare(gy[j])
		case i < len(gx):
			d = -1
		case j < len(gy):
			d = 1
		default:
			return b.String()
		}

		switch d {
		case -1:
			b.WriteString("\n")
			writeHeader("- ", gx[i])
			writeStack("- ", gx[i])
			i++

		case +1:
			b.WriteString("\n")
			writeHeader("+ ", gy[j])
			writeStack("+ ", gy[j])
			j++

		case 0:
			if !bytes.Equal(gx[i].count, gy[j].count) {
				b.WriteString("\n")
				writeHeader("- ", gx[i])
				writeHeader("+ ", gy[j])
				writeStack("  ", gy[j])
			}
			i++
			j++
		}
	}
}
