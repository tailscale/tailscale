// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package state

import (
	"bytes"
	"fmt"
	"sort"
	"time"
)

type statEntry struct {
	count uint
	total time.Duration
}

// Stats tracks encode / decode timing.
//
// This currently provides a meaningful String function and no other way to
// extract stats about individual types.
//
// All exported receivers accept nil.
type Stats struct {
	// byType contains a breakdown of time spent by type.
	//
	// This is indexed *directly* by typeID, including zero.
	byType []statEntry

	// stack contains objects in progress.
	stack []typeID

	// names contains type names.
	//
	// This is also indexed *directly* by typeID, including zero, which we
	// hard-code as "state.default". This is only resolved by calling fini
	// on the stats object.
	names []string

	// last is the last start time.
	last time.Time
}

// init initializes statistics.
func (s *Stats) init() {
	s.last = time.Now()
	s.stack = append(s.stack, 0)
}

// fini finalizes statistics.
func (s *Stats) fini(resolve func(id typeID) string) {
	s.done()

	// Resolve all type names.
	s.names = make([]string, len(s.byType))
	s.names[0] = "state.default" // See above.
	for id := typeID(1); int(id) < len(s.names); id++ {
		s.names[id] = resolve(id)
	}
}

// sample adds the samples to the given object.
func (s *Stats) sample(id typeID) {
	now := time.Now()
	if len(s.byType) <= int(id) {
		// Allocate all the missing entries in one fell swoop.
		s.byType = append(s.byType, make([]statEntry, 1+int(id)-len(s.byType))...)
	}
	s.byType[id].total += now.Sub(s.last)
	s.last = now
}

// start starts a sample.
func (s *Stats) start(id typeID) {
	last := s.stack[len(s.stack)-1]
	s.sample(last)
	s.stack = append(s.stack, id)
}

// done finishes the current sample.
func (s *Stats) done() {
	last := s.stack[len(s.stack)-1]
	s.sample(last)
	s.byType[last].count++
	s.stack = s.stack[:len(s.stack)-1]
}

type sliceEntry struct {
	name  string
	entry *statEntry
}

// String returns a table representation of the stats.
func (s *Stats) String() string {
	// Build a list of stat entries.
	ss := make([]sliceEntry, 0, len(s.byType))
	for id := 0; id < len(s.names); id++ {
		ss = append(ss, sliceEntry{
			name:  s.names[id],
			entry: &s.byType[id],
		})
	}

	// Sort by total time (descending).
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].entry.total > ss[j].entry.total
	})

	// Print the stat results.
	var (
		buf   bytes.Buffer
		count uint
		total time.Duration
	)
	buf.WriteString("\n")
	buf.WriteString(fmt.Sprintf("% 16s | % 8s | % 16s | %s\n", "total", "count", "per", "type"))
	buf.WriteString("-----------------+----------+------------------+----------------\n")
	for _, se := range ss {
		if se.entry.count == 0 {
			// Since we store all types linearly, we are not
			// guaranteed that any entry actually has time.
			continue
		}
		count += se.entry.count
		total += se.entry.total
		per := se.entry.total / time.Duration(se.entry.count)
		buf.WriteString(fmt.Sprintf("% 16s | %8d | % 16s | %s\n",
			se.entry.total, se.entry.count, per, se.name))
	}
	buf.WriteString("-----------------+----------+------------------+----------------\n")
	buf.WriteString(fmt.Sprintf("% 16s | % 8d | % 16s | [all]",
		total, count, total/time.Duration(count)))
	return string(buf.Bytes())
}
