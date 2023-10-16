// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/util/must"
)

func TestDeleter(t *testing.T) {
	dir := t.TempDir()
	must.Do(touchFile(filepath.Join(dir, "foo.partial")))
	must.Do(touchFile(filepath.Join(dir, "bar.partial")))
	must.Do(touchFile(filepath.Join(dir, "fizz")))
	must.Do(touchFile(filepath.Join(dir, "fizz.deleted")))
	must.Do(touchFile(filepath.Join(dir, "buzz.deleted")))

	checkDirectory := func(want ...string) {
		t.Helper()
		var got []string
		for _, de := range must.Get(os.ReadDir(dir)) {
			got = append(got, de.Name())
		}
		slices.Sort(got)
		slices.Sort(want)
		if diff := cmp.Diff(got, want); diff != "" {
			t.Fatalf("directory mismatch (-got +want):\n%s", diff)
		}
	}

	eventChan := make(chan string)
	checkEvent := func(want ...string) {
		t.Helper()
		var got []string
		for range want {
			got = append(got, <-eventChan)
		}
		slices.Sort(got)
		slices.Sort(want)
		if diff := cmp.Diff(got, want); diff != "" {
			t.Fatalf("events mismatch (-got +want):\n%s", diff)
		}
	}

	var fd fileDeleter
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)})
	fd.Init(t.Logf, tstime.DefaultClock{Clock: clock}, func(event string) { eventChan <- event }, dir)
	checkEvent("start init")
	checkEvent("end init", "start waitAndDelete")
	checkDirectory("foo.partial", "bar.partial", "buzz.deleted")

	clock.Advance(deleteDelay / 2)
	checkDirectory("foo.partial", "bar.partial", "buzz.deleted")
	clock.Advance(deleteDelay / 2)
	checkEvent("deleted foo.partial", "deleted bar.partial", "deleted buzz.deleted")
	checkEvent("end waitAndDelete")
	checkDirectory()

	must.Do(touchFile(filepath.Join(dir, "one.partial")))
	fd.Insert("one.partial")
	checkEvent("start waitAndDelete")
	clock.Advance(deleteDelay / 4)
	must.Do(touchFile(filepath.Join(dir, "two.partial")))
	fd.Insert("two.partial")
	clock.Advance(deleteDelay / 4)
	must.Do(touchFile(filepath.Join(dir, "three.partial")))
	fd.Insert("three.partial")
	clock.Advance(deleteDelay / 4)
	must.Do(touchFile(filepath.Join(dir, "four.partial")))
	fd.Insert("four.partial")
	clock.Advance(deleteDelay / 4)
	checkEvent("deleted one.partial")
	checkDirectory("two.partial", "three.partial", "four.partial")
	clock.Advance(deleteDelay / 4)
	checkEvent("end waitAndDelete", "start waitAndDelete")
	checkEvent("deleted two.partial")
	checkDirectory("three.partial", "four.partial")
	clock.Advance(deleteDelay / 4)
	checkEvent("end waitAndDelete", "start waitAndDelete")
	checkEvent("deleted three.partial")
	checkDirectory("four.partial")
	clock.Advance(deleteDelay / 4)
	checkEvent("end waitAndDelete", "start waitAndDelete")
	checkEvent("deleted four.partial")
	checkDirectory()
	checkEvent("end waitAndDelete")

	fd.Insert("wuzz.partial")
	checkEvent("start waitAndDelete")
	fd.Remove("wuzz.partial")
	checkEvent("end waitAndDelete")
}
