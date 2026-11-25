// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package varz

import (
	"bytes"
	"context"
	"expvar"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/metrics"
	"tailscale.com/syncs"
)

func TestParseStreamOpts(t *testing.T) {
	tests := []struct {
		query    string
		interval time.Duration
		nMatch   int
		wantErr  string
	}{
		{query: ""},
		{query: "interval=1s", interval: time.Second},
		{query: "interval=1ms", interval: minStreamInterval},
		{query: "interval=1h", interval: maxStreamInterval},
		{query: "interval=x", wantErr: "bad interval"},
		{query: "interval=", wantErr: "bad interval"},
		{query: "interval=0s", wantErr: "must be positive"},
		{query: "interval=-1s", wantErr: "must be positive"},
		{query: "match=^a&match=b", nMatch: 2},
		{query: "match=(", wantErr: "bad match pattern"},
		{query: strings.Repeat("match=a&", maxMatchPatterns), nMatch: maxMatchPatterns},
		{query: strings.Repeat("match=a&", maxMatchPatterns+1), wantErr: "too many"},
		{query: "match=" + strings.Repeat("a", maxMatchPatternBytes+1), wantErr: "too long"},
	}
	for _, tt := range tests {
		q, err := url.ParseQuery(tt.query)
		if err != nil {
			t.Fatal(err)
		}
		opts, err := parseStreamOpts(q)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("%q: err = %v; want %q", tt.query, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tt.query, err)
			continue
		}
		if opts.interval != tt.interval || len(opts.match) != tt.nMatch {
			t.Errorf("%q: interval=%v, %d patterns; want %v, %d", tt.query, opts.interval, len(opts.match), tt.interval, tt.nMatch)
		}
	}
}

// TestHandlerNilURL checks that the handlers accept a request without
// a URL, as some callers pass new(http.Request).
func TestHandlerNilURL(t *testing.T) {
	rec := httptest.NewRecorder()
	ExpvarDoHandler(newTestVars().do)(rec, new(http.Request))
	if !strings.Contains(rec.Body.String(), "tlb_choose_local 1234\n") {
		t.Errorf("unexpected output:\n%s", rec.Body.Bytes())
	}
}

func TestHandlerBadQuery(t *testing.T) {
	for _, q := range []string{"interval=x", "match=(", "interval=0"} {
		rec := httptest.NewRecorder()
		Handler(rec, httptest.NewRequest("GET", "/debug/varz?"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q: code %v; want 400", q, rec.Code)
		}
	}
}

// testVars is a set of vars for testing filtering and streaming.
type testVars struct {
	local    *expvar.Int
	assigned *metrics.LabelMap
	newPeers *metrics.LabelMap // empty at first
	set      *metrics.Set
	setInner *expvar.Int
	hist     *metrics.Histogram
	other    *expvar.Int
}

func newTestVars() *testVars {
	tv := &testVars{
		local:    new(expvar.Int),
		assigned: &metrics.LabelMap{Label: "peer"},
		newPeers: &metrics.LabelMap{Label: "peer"},
		set:      new(metrics.Set),
		setInner: new(expvar.Int),
		hist:     metrics.NewHistogram([]float64{1, 2}),
		other:    new(expvar.Int),
	}
	tv.local.Set(1234)
	tv.assigned.Add("trunkd102", 77)
	tv.set.Set("counter_inner", tv.setInner)
	tv.hist.Observe(1.5)
	return tv
}

func (tv *testVars) do(f func(expvar.KeyValue)) {
	f(expvar.KeyValue{Key: "counter_tlb_choose_local", Value: tv.local})
	f(expvar.KeyValue{Key: "counter_tlb_assigned", Value: tv.assigned})
	f(expvar.KeyValue{Key: "counter_tlb_new_peers", Value: tv.newPeers})
	f(expvar.KeyValue{Key: "tlbset", Value: tv.set})
	f(expvar.KeyValue{Key: "histogram_lat", Value: tv.hist})
	f(expvar.KeyValue{Key: "gauge_other", Value: tv.other})
	f(expvar.KeyValue{Key: "some_string", Value: new(expvar.String)})
}

func TestOneShotMatch(t *testing.T) {
	tv := newTestVars()
	h := ExpvarDoHandler(tv.do)

	get := func(query string) string {
		t.Helper()
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest("GET", "/debug/varz?"+query, nil))
		if rec.Code != 200 {
			t.Fatalf("%q: code %v: %s", query, rec.Code, rec.Body.Bytes())
		}
		return rec.Body.String()
	}

	var all bytes.Buffer
	varzSource{do: tv.do}.writeTo(&all)
	if got := get("unrelated=1"); got != all.String() {
		t.Errorf("unrelated param changed output:\n%s\nwant:\n%s", got, all.Bytes())
	}

	got := get("match=^tlb_&match=^lat$&match=^tlbset_inner$")
	want := `# TYPE lat histogram
lat_bucket{le="1"} 0
lat_bucket{le="2"} 1
lat_bucket{le="+Inf"} 1
lat_sum 1.5
lat_count 1
# TYPE tlb_assigned counter
tlb_assigned{peer="trunkd102"} 77
# TYPE tlb_choose_local counter
tlb_choose_local 1234
# TYPE tlbset_inner counter
tlbset_inner 0
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}

	// Matching only a histogram sample name includes the family's metadata.
	if got, want := get("match=^lat_sum$"), "# TYPE lat histogram\nlat_sum 1.5\n"; got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if got := get("match=^nope$"); got != "" {
		t.Errorf("got %q; want empty", got)
	}
}

// streamWriter is an [http.ResponseWriter] and [http.Flusher] that
// records what's written and flushed.
type streamWriter struct {
	mu      sync.Mutex
	header  http.Header
	buf     bytes.Buffer // flushed, unread
	pending bytes.Buffer // written, not yet flushed
}

func (w *streamWriter) Header() http.Header { return w.header }
func (w *streamWriter) WriteHeader(int)     {}

func (w *streamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pending.Write(p)
}

func (w *streamWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(w.pending.Bytes())
	w.pending.Reset()
}

// next returns and removes the flushed output.
func (w *streamWriter) next() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.buf.String()
	w.buf.Reset()
	return s
}

func TestStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tv := newTestVars()
		h := ExpvarDoHandler(tv.do)
		w := &streamWriter{header: http.Header{}}
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest("GET", "/debug/varz?interval=1s&match=^tlb&match=^lat$", nil).WithContext(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			h(w, req)
		}()

		check := func(want string) {
			t.Helper()
			synctest.Wait()
			if got := w.next(); got != want {
				t.Errorf("got:\n%s\nwant:\n%s", got, want)
			}
		}
		check(`# TIME 2000-01-01T00:00:00.000000000Z full
# TYPE lat histogram
lat_bucket{le="1"} 0
lat_bucket{le="2"} 1
lat_bucket{le="+Inf"} 1
lat_sum 1.5
lat_count 1
# TYPE tlb_assigned counter
tlb_assigned{peer="trunkd102"} 77
# TYPE tlb_choose_local counter
tlb_choose_local 1234
# TYPE tlbset_inner counter
tlbset_inner 0
# EOF

`)
		if got, want := w.Header().Get("Content-Type"), contentType; got != want {
			t.Errorf("Content-Type = %q; want %q", got, want)
		}

		tv.local.Add(6)
		tv.other.Add(1) // not matched
		time.Sleep(time.Second)
		check(`# TIME 2000-01-01T00:00:01.000000000Z delta
tlb_choose_local 1240
# EOF

`)

		time.Sleep(time.Second)
		check("# TIME 2000-01-01T00:00:02.000000000Z delta\n# EOF\n\n")

		// A new key in an existing LabelMap resends that LabelMap's
		// other series without a TYPE line, while the first key of a
		// new LabelMap comes with one.
		tv.assigned.Add("trunkd103", 1)
		tv.newPeers.Add("a", 1)
		tv.hist.Observe(0.5)
		time.Sleep(time.Second)
		check(`# TIME 2000-01-01T00:00:03.000000000Z delta
lat_bucket{le="1"} 1
lat_bucket{le="2"} 2
lat_bucket{le="+Inf"} 2
lat_sum 2
lat_count 2
tlb_assigned{peer="trunkd102"} 77
tlb_assigned{peer="trunkd103"} 1
# TYPE tlb_new_peers counter
tlb_new_peers{peer="a"} 1
# EOF

`)

		tv.newPeers.Add("a", 1)
		time.Sleep(time.Second)
		check(`# TIME 2000-01-01T00:00:04.000000000Z delta
tlb_new_peers{peer="a"} 2
# EOF

`)

		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("handler didn't return after cancel")
		}
	})
}

func TestStreamComments(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tv := newTestVars()
		h := ExpvarDoHandler(tv.do)
		w := &streamWriter{header: http.Header{}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go h(w, httptest.NewRequest("GET", "/debug/varz?interval=1s", nil).WithContext(ctx))
		synctest.Wait()
		full := w.next()
		if !strings.Contains(full, "# skipping expvar \"some_string\"") {
			t.Errorf("full frame lacks skipping comment:\n%s", full)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if got, want := w.next(), "# TIME 2000-01-01T00:00:01.000000000Z delta\n# EOF\n\n"; got != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})
}

func TestStreamLimit(t *testing.T) {
	for range maxStreams {
		streamSem <- struct{}{}
	}
	defer func() {
		for range maxStreams {
			<-streamSem
		}
	}()
	rec := httptest.NewRecorder()
	Handler(rec, httptest.NewRequest("GET", "/debug/varz?interval=1s", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("code %v; want 503", rec.Code)
	}
}

func TestReadStream(t *testing.T) {
	const in = `# TIME 2026-11-24T18:03:01.000123456Z full
# TYPE tlb_choose_local counter
tlb_choose_local 1234
tlb_assigned{peer="trunk d102"} 77
# EOF

# TIME 2026-11-24T18:03:02.000098765Z delta
# EOF

`
	var frames []*Frame
	err := ReadStream(strings.NewReader(in), func(f *Frame) error {
		frames = append(frames, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("got %d frames; want 2", len(frames))
	}
	f0, f1 := frames[0], frames[1]
	if !f0.Full || f1.Full {
		t.Errorf("Full = %v, %v; want true, false", f0.Full, f1.Full)
	}
	if want := time.Date(2026, 11, 24, 18, 3, 1, 123456, time.UTC); !f0.Time.Equal(want) {
		t.Errorf("Time = %v; want %v", f0.Time, want)
	}
	if len(f0.Samples) != 2 || f0.Samples["tlb_choose_local"] != 1234 || f0.Samples[`tlb_assigned{peer="trunk d102"}`] != 77 {
		t.Errorf("Samples = %v", f0.Samples)
	}
	if len(f1.Samples) != 0 {
		t.Errorf("delta Samples = %v; want empty", f1.Samples)
	}

	truncated := in[:strings.LastIndex(in, "# EOF")]
	n := 0
	err = ReadStream(strings.NewReader(truncated), func(*Frame) error { n++; return nil })
	if err != io.ErrUnexpectedEOF || n != 1 {
		t.Errorf("truncated: n=%d, err=%v; want 1, ErrUnexpectedEOF", n, err)
	}
}

// TestStreamRoundTrip checks that [ReadStream] parses what the handler
// writes, including the runtime metrics from [Handler].
func TestStreamRoundTrip(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(Handler))
	defer ts.Close()
	res, err := http.Get(ts.URL + "/debug/varz?interval=100ms&match=^go_runtime_&match=^memstats_&match=^uptime_sec$")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var frames []*Frame
	err = ReadStream(res.Body, func(f *Frame) error {
		frames = append(frames, f)
		if len(frames) == 3 {
			return io.EOF
		}
		return nil
	})
	if err != io.EOF {
		t.Fatalf("ReadStream: %v", err)
	}
	if !frames[0].Full || frames[1].Full || frames[2].Full {
		t.Errorf("frame kinds wrong")
	}
	if _, ok := frames[0].Samples["memstats_heap_alloc"]; !ok {
		t.Errorf("first frame lacks memstats_heap_alloc: %v", frames[0].Samples)
	}
	if _, ok := frames[0].Samples["uptime_sec"]; !ok {
		t.Errorf("first frame lacks uptime_sec")
	}
	if !frames[1].Time.After(frames[0].Time) {
		t.Errorf("frame times not increasing")
	}
}

// TestStreamReadsOnlyMatches checks that a stream reads each var once
// at setup, and after that only the vars that matched.
func TestStreamReadsOnlyMatches(t *testing.T) {
	calls := map[string]int{}
	countingFunc := func(name string) expvar.Func {
		return func() any {
			calls[name]++
			return 1
		}
	}
	set := new(metrics.Set)
	set.Set("gauge_hit", countingFunc("set_hit"))
	set.Set("gauge_miss", countingFunc("set_miss"))
	do := func(f func(expvar.KeyValue)) {
		f(expvar.KeyValue{Key: "gauge_tlb_hit", Value: countingFunc("hit")})
		f(expvar.KeyValue{Key: "gauge_miss", Value: countingFunc("miss")})
		f(expvar.KeyValue{Key: "s", Value: set})
	}

	rec := httptest.NewRecorder()
	ExpvarDoHandler(do)(rec, httptest.NewRequest("GET", "/debug/varz?match=^tlb_&match=^s_hit$", nil))
	if got, want := rec.Body.String(), "# TYPE s_hit gauge\ns_hit 1\n# TYPE tlb_hit gauge\ntlb_hit 1\n"; got != want {
		t.Errorf("one-shot got %q; want %q", got, want)
	}

	clear(calls)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := &streamWriter{header: http.Header{}}
		go ExpvarDoHandler(do)(w, httptest.NewRequest("GET", "/debug/varz?interval=1s&match=^tlb_", nil).WithContext(ctx))
		time.Sleep(2500 * time.Millisecond)
		synctest.Wait()
		// Each func is read once at setup, then "hit" once per frame.
		want := map[string]int{"hit": 4, "miss": 1, "set_hit": 1, "set_miss": 1}
		if !maps.Equal(calls, want) {
			t.Errorf("stream calls = %v; want %v", calls, want)
		}
	})
}

// TestStreamRescan checks that a stream picks up vars added after it
// started.
func TestStreamRescan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		kvs := []expvar.KeyValue{{Key: "counter_tlb_a", Value: new(expvar.Int)}}
		do := func(f func(expvar.KeyValue)) {
			mu.Lock()
			defer mu.Unlock()
			for _, kv := range kvs {
				f(kv)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := &streamWriter{header: http.Header{}}
		go ExpvarDoHandler(do)(w, httptest.NewRequest("GET", "/debug/varz?interval=1s&match=^tlb_", nil).WithContext(ctx))
		synctest.Wait()
		w.next()

		b := new(expvar.Int)
		b.Set(5)
		mu.Lock()
		kvs = append(kvs, expvar.KeyValue{Key: "gauge_tlb_b", Value: b})
		mu.Unlock()

		time.Sleep(rescanInterval - time.Second)
		synctest.Wait()
		if got := w.next(); strings.Contains(got, "tlb_b") {
			t.Errorf("new var appeared before rescan:\n%s", got)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if got, want := w.next(), "# TIME 2000-01-01T00:00:10.000000000Z delta\n# TYPE tlb_b gauge\ntlb_b 5\n# EOF\n\n"; got != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})
}

// TestScalarFormat checks that the scalar fast path formats values
// exactly as a one-shot request does.
func TestScalarFormat(t *testing.T) {
	values := []any{
		0, -1, int8(-8), int64(math.MinInt64), uint64(math.MaxUint64), uint8(255), uintptr(7),
		0.1, 1e21, 1e-7, 123456789.0, math.Inf(1), math.Inf(-1), math.NaN(), math.Copysign(0, -1),
		float32(0.1), float32(1e21),
	}
	for _, v := range values {
		for _, key := range []string{"foo", "gauge_foo"} {
			var vf expvar.Var = expvar.Func(func() any { return v })
			if f, ok := v.(float64); ok && key == "foo" {
				ev := new(expvar.Float)
				ev.Set(f)
				vf = ev
			}
			do := func(f func(expvar.KeyValue)) { f(expvar.KeyValue{Key: key, Value: vf}) }
			src := varzSource{do: do}
			var want bytes.Buffer
			src.writeTo(&want)
			st := newVarzStream(src, nil)
			if _, ok := st.vars[0].v.(*scalarVar); !ok && !strings.Contains(want.String(), "# skipping") {
				t.Errorf("%s=%T(%v): got %T; want *scalarVar", key, v, v, st.vars[0].v)
			}
			if got := st.appendFrame(nil, true); string(got) != want.String() {
				t.Errorf("%s=%T(%v): got %q; want %q", key, v, v, got, want.Bytes())
			}
		}
	}
}

func TestStreamSteadyStateAllocs(t *testing.T) {
	set := new(metrics.Set)
	set.Set("counter_a", new(expvar.Int))
	set.Set("gauge_b", new(expvar.Float))
	var boxed any = 42
	sharded := syncs.NewShardedInt()
	do := func(f func(expvar.KeyValue)) {
		f(expvar.KeyValue{Key: "counter_x", Value: new(expvar.Int)})
		f(expvar.KeyValue{Key: "counter_sharded", Value: sharded})
		f(expvar.KeyValue{Key: "gauge_func", Value: expvar.Func(func() any { return boxed })})
		f(expvar.KeyValue{Key: "s", Value: set})
	}
	st := newVarzStream(varzSource{do: do}, nil)
	dst := st.appendFrame(nil, true)
	got := testing.AllocsPerRun(100, func() {
		sharded.Add(1)
		dst = st.appendFrame(dst[:0], false)
	})
	if got != 0 {
		t.Errorf("allocs = %v; want 0", got)
	}
	if want := "sharded 101\n"; string(dst) != want {
		t.Errorf("delta = %q; want %q", dst, want)
	}
}

// benchVars returns a do func for 1000 counters (10 of them named
// tlb_*), 20 LabelMaps of 50 keys each, and a Set of 100 counters.
func benchVars() func(func(expvar.KeyValue)) {
	var kvs []expvar.KeyValue
	for i := range 1000 {
		v := new(expvar.Int)
		v.Set(int64(i))
		name := fmt.Sprintf("counter_x%d", i)
		if i < 10 {
			name = fmt.Sprintf("counter_tlb_%d", i)
		}
		kvs = append(kvs, expvar.KeyValue{Key: name, Value: v})
	}
	for i := range 20 {
		lm := &metrics.LabelMap{Label: "k"}
		for j := range 50 {
			lm.Add(fmt.Sprint(j), int64(j))
		}
		kvs = append(kvs, expvar.KeyValue{Key: fmt.Sprintf("counter_lm%d", i), Value: lm})
	}
	set := new(metrics.Set)
	for i := range 100 {
		set.Set(fmt.Sprintf("counter_m%d", i), new(expvar.Int))
	}
	kvs = append(kvs, expvar.KeyValue{Key: "set", Value: set})
	return func(f func(expvar.KeyValue)) {
		for _, kv := range kvs {
			f(kv)
		}
	}
}

func BenchmarkOneShot(b *testing.B) {
	src := varzSource{do: benchVars()}
	b.ReportAllocs()
	for b.Loop() {
		src.writeTo(io.Discard)
	}
}

func BenchmarkStreamDelta(b *testing.B) {
	for _, bb := range []struct {
		name string
		sel  []string
	}{
		{"match", []string{"^tlb_"}},
		{"all", nil},
	} {
		b.Run(bb.name, func(b *testing.B) {
			opts, err := parseStreamOpts(url.Values{"match": bb.sel})
			if err != nil {
				b.Fatal(err)
			}
			st := newVarzStream(varzSource{do: benchVars()}, opts.match)
			buf := st.appendFrame(nil, true)
			b.ReportAllocs()
			for b.Loop() {
				buf = st.appendFrame(buf[:0], false)
			}
		})
	}
}
