// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package prober

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/tstest"
)

const (
	probeInterval        = 10 * time.Second // So expvars that are integer numbers of seconds change
	halfProbeInterval    = probeInterval / 2
	quarterProbeInterval = probeInterval / 4
	convergenceTimeout   = time.Second
	convergenceSleep     = time.Millisecond
)

var epoch = time.Unix(0, 0)

func TestProberTiming(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker)

	invoked := make(chan struct{}, 1)

	notCalled := func() {
		t.Helper()
		select {
		case <-invoked:
			t.Fatal("probe was invoked earlier than expected")
		default:
		}
	}
	called := func() {
		t.Helper()
		select {
		case <-invoked:
		case <-time.After(2 * time.Second):
			t.Fatal("probe wasn't invoked as expected")
		}
	}

	p.Run("test-probe", probeInterval, func(context.Context) error {
		invoked <- struct{}{}
		return nil
	})

	waitActiveProbes(t, p, 1)

	notCalled()
	clk.Advance(probeInterval + halfProbeInterval)
	called()
	notCalled()
	clk.Advance(quarterProbeInterval)
	notCalled()
	clk.Advance(probeInterval)
	called()
	notCalled()
}

func TestProberRun(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker)

	var (
		mu  sync.Mutex
		cnt int
	)

	const startingProbes = 100
	cancels := []context.CancelFunc{}

	for i := 0; i < startingProbes; i++ {
		cancels = append(cancels, p.Run(fmt.Sprintf("probe%d", i), probeInterval, func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			cnt++
			return nil
		}))
	}

	checkCnt := func(want int) {
		err := tstest.WaitFor(convergenceTimeout, func() error {
			mu.Lock()
			defer mu.Unlock()
			if cnt == want {
				cnt = 0
				return nil
			}
			return fmt.Errorf("wrong number of probe counter increments, got %d want %d", cnt, want)
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	waitActiveProbes(t, p, startingProbes)
	clk.Advance(probeInterval + halfProbeInterval)
	checkCnt(startingProbes)

	keep := startingProbes / 2

	for i := keep; i < startingProbes; i++ {
		cancels[i]()
	}
	waitActiveProbes(t, p, keep)

	clk.Advance(probeInterval)
	checkCnt(keep)
}

func TestExpvar(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker)

	const aFewMillis = 20 * time.Millisecond
	var succeed syncs.AtomicBool
	p.Run("probe", probeInterval, func(context.Context) error {
		clk.Advance(aFewMillis)
		if succeed.Get() {
			return nil
		}
		return errors.New("failing, as instructed by test")
	})

	waitActiveProbes(t, p, 1)
	clk.Advance(probeInterval + halfProbeInterval)

	waitExpInt(t, p, "start_secs/probe", int((probeInterval + halfProbeInterval).Seconds()))
	waitExpInt(t, p, "end_secs/probe", int((probeInterval + halfProbeInterval).Seconds()))
	waitExpInt(t, p, "interval_secs/probe", int(probeInterval.Seconds()))
	waitExpInt(t, p, "latency_millis/probe", int(aFewMillis.Milliseconds()))
	waitExpInt(t, p, "result/probe", 0)

	succeed.Set(true)
	clk.Advance(probeInterval)

	waitExpInt(t, p, "start_secs/probe", int((probeInterval + probeInterval + halfProbeInterval).Seconds()))
	waitExpInt(t, p, "end_secs/probe", int((probeInterval + probeInterval + halfProbeInterval).Seconds()))
	waitExpInt(t, p, "interval_secs/probe", int(probeInterval.Seconds()))
	waitExpInt(t, p, "latency_millis/probe", int(aFewMillis.Milliseconds()))
	waitExpInt(t, p, "result/probe", 1)
}

type fakeTicker struct {
	ch       chan time.Time
	interval time.Duration

	sync.Mutex
	next    time.Time
	stopped bool
}

func (t *fakeTicker) Chan() <-chan time.Time {
	return t.ch
}

func (t *fakeTicker) Stop() {
	t.Lock()
	defer t.Unlock()
	t.stopped = true
}

func (t *fakeTicker) fire(now time.Time) {
	t.Lock()
	defer t.Unlock()
	// Slight deviation from the stdlib ticker: time.Ticker will
	// adjust t.next to make up for missed ticks, whereas we tick on a
	// fixed interval regardless of receiver behavior. In our case
	// this is fine, since we're using the ticker as a wakeup
	// mechanism and not a precise timekeeping system.
	select {
	case t.ch <- now:
	default:
	}
	t.next = now.Add(t.interval)
}

type fakeTime struct {
	sync.Mutex
	*sync.Cond
	curTime time.Time
	tickers []*fakeTicker
}

func newFakeTime() *fakeTime {
	ret := &fakeTime{
		curTime: epoch,
	}
	ret.Cond = &sync.Cond{L: &ret.Mutex}
	ret.Advance(time.Duration(1)) // so that Now never IsZero
	return ret
}

func (t *fakeTime) Now() time.Time {
	t.Lock()
	defer t.Unlock()
	ret := t.curTime
	// so that time always seems to advance for the program under test
	t.curTime = t.curTime.Add(time.Microsecond)
	return ret
}

func (t *fakeTime) NewTicker(d time.Duration) ticker {
	t.Lock()
	defer t.Unlock()
	ret := &fakeTicker{
		ch:       make(chan time.Time, 1),
		interval: d,
		next:     t.curTime.Add(d),
	}
	t.tickers = append(t.tickers, ret)
	t.Cond.Broadcast()
	return ret
}

func (t *fakeTime) Advance(d time.Duration) {
	t.Lock()
	defer t.Unlock()
	t.curTime = t.curTime.Add(d)
	for _, tick := range t.tickers {
		if t.curTime.After(tick.next) {
			tick.fire(t.curTime)
		}
	}
}

func waitExpInt(t *testing.T, p *Prober, path string, want int) {
	t.Helper()
	err := tstest.WaitFor(convergenceTimeout, func() error {
		got, ok := getExpInt(t, p, path)
		if !ok {
			return fmt.Errorf("expvar %q did not get set", path)
		}
		if got != want {
			return fmt.Errorf("expvar %q is %d, want %d", path, got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func getExpInt(t *testing.T, p *Prober, path string) (ret int, ok bool) {
	t.Helper()
	s := p.Expvar().String()
	dec := map[string]interface{}{}
	if err := json.Unmarshal([]byte(s), &dec); err != nil {
		t.Fatalf("couldn't unmarshal expvar data: %v", err)
	}
	var v interface{} = dec
	for _, d := range strings.Split(path, "/") {
		m, ok := v.(map[string]interface{})
		if !ok {
			t.Fatalf("expvar path %q ended early with a leaf value", path)
		}
		child, ok := m[d]
		if !ok {
			return 0, false
		}
		v = child
	}
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int(f), true
}

func waitActiveProbes(t *testing.T, p *Prober, want int) {
	t.Helper()
	err := tstest.WaitFor(convergenceTimeout, func() error {
		if got := p.activeProbes(); got != want {
			return fmt.Errorf("active probe count is %d, want %d", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
