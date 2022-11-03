// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstest

import (
	"bytes"
	"compress/gzip"
	"io"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"tailscale.com/tstest/profilepb"
)

func ResourceCheck(tb testing.TB) {
	tb.Helper()
	startN, startStacks := goroutines()
	tb.Cleanup(func() {
		if tb.Failed() {
			// Something else went wrong.
			return
		}
		// Goroutines might be still exiting.
		for i := 0; i < 100; i++ {
			if runtime.NumGoroutine() <= startN {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		filteredGoroutines := numGoroutines(tb, pprof.Lookup("goroutine"))
		if filteredGoroutines <= startN {
			return
		}
		endN, endStacks := goroutines()
		tb.Logf("goroutine diff:\n%v\n", cmp.Diff(startStacks, endStacks))
		tb.Fatalf("goroutine count: expected %d, got %d (%d filtered)\n", startN, endN, filteredGoroutines)
	})
}

func goroutines() (int, []byte) {
	p := pprof.Lookup("goroutine")
	b := new(bytes.Buffer)
	p.WriteTo(b, 1)
	return p.Count(), b.Bytes()
}

var ignoredGoroutineStarts = map[string]bool{
	"net.cgoIPLookup": true,
}

func numGoroutines(tb testing.TB, p *pprof.Profile) int {
	b := new(bytes.Buffer)
	p.WriteTo(b, 0) // gzip-compressed protobuf format

	zr, err := gzip.NewReader(b)
	if err != nil {
		tb.Logf("error creating gzip.Reader: %v", err)
		return -1
	}
	pb, err := io.ReadAll(zr)
	if err != nil {
		tb.Logf("error decompressing profile: %v", err)
		return -1
	}

	var prof profilepb.Profile
	if err := proto.Unmarshal(pb, &prof); err != nil {
		tb.Logf("error parsing profile: %v", err)
		return -1
	}

	var (
		functions = make(map[uint64]*profilepb.Function)
		locations = make(map[uint64]*profilepb.Location)
	)
	for _, f := range prof.Function {
		functions[f.Id] = f
	}
	for _, m := range prof.Location {
		locations[m.Id] = m
	}

	var num int64
	for _, sample := range prof.Sample {
		skip := false
		for _, locid := range sample.LocationId {
			loc := locations[locid]
			for _, line := range loc.Line {
				fn := functions[line.FunctionId]
				fname := prof.StringTable[fn.Name]
				if ignoredGoroutineStarts[fname] {
					tb.Logf("skipping goroutine: %s", fname)
					skip = true
					break
				}
			}
			if skip {
				break
			}
		}
		if skip {
			continue
		}

		for _, val := range sample.Value {
			num += val
		}
	}

	return int(num)
}
