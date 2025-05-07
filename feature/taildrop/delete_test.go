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
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
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
	must.Do(touchFile(filepath.Join(dir, "buzz.deleted"))) // lacks a matching "buzz" file

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

	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)})
	advance := func(d time.Duration) {
		t.Helper()
		t.Logf("advance: %v", d)
		clock.Advance(d)
	}

	eventsChan := make(chan string, 1000)
	checkEvents := func(want ...string) {
		t.Helper()
		tm := time.NewTimer(10 * time.Second)
		defer tm.Stop()
		var got []string
		for range want {
			select {
			case event := <-eventsChan:
				t.Logf("event: %s", event)
				got = append(got, event)
			case <-tm.C:
				t.Fatalf("timed out waiting for event: got %v, want %v", got, want)
			}
		}
		slices.Sort(got)
		slices.Sort(want)
		if diff := cmp.Diff(got, want); diff != "" {
			t.Fatalf("events mismatch (-got +want):\n%s", diff)
		}
	}
	eventHook := func(event string) { eventsChan <- event }

	var m manager
	var fd fileDeleter
	m.opts.Logf = t.Logf
	m.opts.Clock = tstime.DefaultClock{Clock: clock}
	m.opts.Dir = dir
	m.opts.State = must.Get(mem.New(nil, ""))
	must.Do(m.opts.State.WriteState(ipn.TaildropReceivedKey, []byte{1}))
	fd.Init(&m, eventHook)
	defer fd.Shutdown()
	insert := func(name string) {
		t.Helper()
		t.Logf("insert: %v", name)
		fd.Insert(name)
	}
	remove := func(name string) {
		t.Helper()
		t.Logf("remove: %v", name)
		fd.Remove(name)
	}

	checkEvents("start full-scan")
	checkEvents("end full-scan", "start waitAndDelete")
	checkDirectory("foo.partial", "bar.partial", "buzz.deleted")

	advance(deleteDelay / 2)
	checkDirectory("foo.partial", "bar.partial", "buzz.deleted")
	advance(deleteDelay / 2)
	checkEvents("deleted foo.partial", "deleted bar.partial", "deleted buzz.deleted")
	checkEvents("end waitAndDelete")
	checkDirectory()

	must.Do(touchFile(filepath.Join(dir, "one.partial")))
	insert("one.partial")
	checkEvents("start waitAndDelete")
	advance(deleteDelay / 4)
	must.Do(touchFile(filepath.Join(dir, "two.partial")))
	insert("two.partial")
	advance(deleteDelay / 4)
	must.Do(touchFile(filepath.Join(dir, "three.partial")))
	insert("three.partial")
	advance(deleteDelay / 4)
	must.Do(touchFile(filepath.Join(dir, "four.partial")))
	insert("four.partial")

	advance(deleteDelay / 4)
	checkEvents("deleted one.partial")
	checkDirectory("two.partial", "three.partial", "four.partial")
	checkEvents("end waitAndDelete", "start waitAndDelete")

	advance(deleteDelay / 4)
	checkEvents("deleted two.partial")
	checkDirectory("three.partial", "four.partial")
	checkEvents("end waitAndDelete", "start waitAndDelete")

	advance(deleteDelay / 4)
	checkEvents("deleted three.partial")
	checkDirectory("four.partial")
	checkEvents("end waitAndDelete", "start waitAndDelete")

	advance(deleteDelay / 4)
	checkEvents("deleted four.partial")
	checkDirectory()
	checkEvents("end waitAndDelete")

	insert("wuzz.partial")
	checkEvents("start waitAndDelete")
	remove("wuzz.partial")
	checkEvents("end waitAndDelete")
}

// Test that the asynchronous full scan of the taildrop directory does not occur
// on a cold start if taildrop has never received any files.
func TestDeleterInitWithoutTaildrop(t *testing.T) {
	var m manager
	var fd fileDeleter
	m.opts.Logf = t.Logf
	m.opts.Dir = t.TempDir()
	m.opts.State = must.Get(mem.New(nil, ""))
	fd.Init(&m, func(event string) { t.Errorf("unexpected event: %v", event) })
	fd.Shutdown()
}
