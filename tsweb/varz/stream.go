// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package varz

import (
	"bufio"
	"bytes"
	"errors"
	"expvar"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tailscale.com/metrics"
	"tailscale.com/syncs"
)

// Limits on the query parameters of [Handler] and [ExpvarDoHandler].
const (
	minStreamInterval    = 100 * time.Millisecond
	maxStreamInterval    = time.Minute
	maxMatchPatterns     = 32
	maxMatchPatternBytes = 4 << 10 // total length of all match patterns
	maxStreams           = 16      // concurrent streams per process
	minStreamWriteWait   = 5 * time.Second
	rescanInterval       = 10 * time.Second // how often a stream looks for new vars
)

// streamSem bounds the number of concurrent streams.
var streamSem = make(chan struct{}, maxStreams)

// frameTimeFormat is RFC 3339 with a fixed nine digits of fractional
// seconds, so frame headers have a constant width.
const frameTimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

// streamOpts are the parsed query parameters of a /debug/varz request.
type streamOpts struct {
	interval time.Duration // or zero for a one-shot response
	match    selector
}

// parseStreamOpts parses the "interval" and "match" query parameters
// of a /debug/varz request. It clamps the interval to
// [minStreamInterval, maxStreamInterval].
func parseStreamOpts(q url.Values) (streamOpts, error) {
	var opts streamOpts
	if q.Has("interval") {
		d, err := time.ParseDuration(q.Get("interval"))
		if err != nil {
			return opts, fmt.Errorf("bad interval: %v", err)
		}
		if d <= 0 {
			return opts, errors.New("bad interval: must be positive")
		}
		opts.interval = min(max(d, minStreamInterval), maxStreamInterval)
	}
	pats := q["match"]
	if len(pats) > maxMatchPatterns {
		return opts, fmt.Errorf("too many match patterns; max %d", maxMatchPatterns)
	}
	total := 0
	for _, p := range pats {
		total += len(p)
	}
	if total > maxMatchPatternBytes {
		return opts, fmt.Errorf("match patterns too long; max %d bytes total", maxMatchPatternBytes)
	}
	for _, p := range pats {
		re, err := regexp.Compile(p)
		if err != nil {
			return opts, fmt.Errorf("bad match pattern: %v", err)
		}
		opts.match = append(opts.match, re)
	}
	return opts, nil
}

// serveQuery serves a /debug/varz request that has a query string.
func (s varzSource) serveQuery(w http.ResponseWriter, r *http.Request) {
	opts, err := parseStreamOpts(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch {
	case opts.interval > 0:
		select {
		case streamSem <- struct{}{}:
			defer func() { <-streamSem }()
		default:
			http.Error(w, "too many concurrent varz streams", http.StatusServiceUnavailable)
			return
		}
		newVarzStream(s, opts.match).serve(w, r, opts.interval)
	case len(opts.match) > 0:
		w.Header().Set("Content-Type", contentType)
		w.Write(newVarzStream(s, opts.match).appendFrame(nil, true))
	default:
		w.Header().Set("Content-Type", contentType)
		s.writeTo(w)
	}
}

// countVars returns the number of vars in s, counting the members of
// each [metrics.Set] as well as the set itself.
func (s varzSource) countVars() int {
	n := 0
	var count func(expvar.KeyValue)
	count = func(kv expvar.KeyValue) {
		n++
		if set, ok := kv.Value.(*metrics.Set); ok {
			set.Do(count)
		}
	}
	s.do(count)
	return n
}

// selector selects series by metric name. An empty selector selects
// everything.
type selector []*regexp.Regexp

func (sel selector) all() bool { return len(sel) == 0 }

func (sel selector) matches(name []byte) bool {
	if sel.all() {
		return true
	}
	for _, re := range sel {
		if re.Match(name) {
			return true
		}
	}
	return false
}

// varzStream is the state of a filtered or streaming /debug/varz
// response.
//
// It decides once which vars might match, and remembers what it last
// sent of each, so later frames neither revisit vars that can't match
// nor format values that didn't change. It only learns of vars added
// later when [varzSource.countVars] changes.
type varzStream struct {
	src   varzSource
	sel   selector
	vars  []streamEntry // in output order
	nVars int           // src.countVars() as of the last build
	kvs   sortedKVs     // scratch space for build
}

type streamEntry struct {
	key string // var key, with Set members prefixed by their Set's name
	v   streamVar
}

// streamVar is a source of lines in a stream: a var, or the Go
// runtime metrics.
type streamVar interface {
	// appendFrame appends to dst the lines for the next frame and
	// returns the extended slice. If full, that's every series that
	// sel matches. Otherwise it's only those that changed since the
	// previous call, along with any metadata not yet sent.
	appendFrame(dst []byte, full bool, sel selector) []byte
}

// runtimeKey is the streamEntry key for the Go runtime metrics. Its
// leading NUL byte keeps it from plausibly colliding with a var key.
const runtimeKey = "\x00runtime"

func newVarzStream(src varzSource, sel selector) *varzStream {
	st := &varzStream{src: src, sel: sel}
	st.build()
	return st
}

// build finds the vars that might produce series st.sel matches,
// keeping the state of any it already had.
func (st *varzStream) build() {
	old := make(map[string]streamVar, len(st.vars))
	for _, e := range st.vars {
		old[e.key] = e.v
	}
	st.vars = st.vars[:0]
	st.nVars = st.src.countVars()
	st.src.sortVars(&st.kvs)
	for _, e := range st.kvs.kvs {
		st.addVar("", e.KeyValue, old)
	}
	clear(st.kvs.kvs)
	if st.src.runtime {
		st.add(runtimeKey, "", nil, func(w io.Writer) { runtimeMetrics.writeTo(w) }, old)
	}
}

// addVar adds kv, whose metric name is prefixed by prefix, or each of
// its members if it's a [metrics.Set].
func (st *varzStream) addVar(prefix string, kv expvar.KeyValue, old map[string]streamVar) {
	name, _, _ := prometheusMetric(prefix, kv.Key)
	if set, ok := kv.Value.(*metrics.Set); ok {
		set.Do(func(kv expvar.KeyValue) {
			st.addVar(name+"_", kv, old)
		})
		return
	}
	st.add(prefix+kv.Key, name, kv.Value, func(w io.Writer) { writePromExpVar(w, prefix, kv) }, old)
}

// add adds the var v (or nil for the runtime metrics) with the given
// key and metric name if any series or metadata it renders now matches
// st.sel.
func (st *varzStream) add(key, name string, v expvar.Var, render func(io.Writer), old map[string]streamVar) {
	if sv, ok := old[key]; ok {
		st.vars = append(st.vars, streamEntry{key, sv})
		return
	}
	var w appendWriter
	render(&w)
	buf := ensureNewline(w.b)
	lines := parseLines(nil, buf)
	if !st.sel.all() && !(name != "" && st.sel.matches([]byte(name))) && !anyMatch(buf, lines, st.sel) {
		return
	}
	var sv streamVar
	if s := newScalarVar(v, name, buf, lines); s != nil {
		sv = s
	} else if len(buf) > 0 && !hasSeries(lines) {
		sv = commentVar(buf)
	} else {
		sv = &renderedVar{render: render, w: appendWriter{buf}, lines: lines, fresh: true}
	}
	st.vars = append(st.vars, streamEntry{key, sv})
}

// appendFrame appends st's next frame, without its "# TIME" and "# EOF"
// lines, to dst and returns the extended slice.
func (st *varzStream) appendFrame(dst []byte, full bool) []byte {
	for _, e := range st.vars {
		dst = e.v.appendFrame(dst, full, st.sel)
	}
	return dst
}

// serve streams st to w at the given interval until the client goes
// away or a write fails.
func (st *varzStream) serve(w http.ResponseWriter, r *http.Request, interval time.Duration) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", "no-cache")
	rc := http.NewResponseController(w)
	writeWait := max(3*interval, minStreamWriteWait)
	defer rc.SetWriteDeadline(time.Time{})

	var frame []byte
	t := time.NewTicker(interval)
	defer t.Stop()
	lastScan := time.Now()
	for full := true; ; full = false {
		now := time.Now()
		if now.Sub(lastScan) >= rescanInterval {
			lastScan = now
			if st.src.countVars() != st.nVars {
				st.build()
			}
		}

		frame = append(frame[:0], "# TIME "...)
		frame = now.UTC().AppendFormat(frame, frameTimeFormat)
		if full {
			frame = append(frame, " full\n"...)
		} else {
			frame = append(frame, " delta\n"...)
		}
		frame = st.appendFrame(frame, full)
		frame = append(frame, "# EOF\n\n"...)

		rc.SetWriteDeadline(time.Now().Add(writeWait)) // ErrNotSupported is fine
		if _, err := w.Write(frame); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
		}
	}
}

// scalarVar is a var with a single unlabeled sample whose value can be
// read and compared without formatting it.
type scalarVar struct {
	v      expvar.Var // *expvar.Int, *syncs.ShardedInt, *expvar.Float, or expvar.Func
	meta   []byte     // metadata lines
	prefix []byte     // sample line up to its value, such as "foo "
	last   number     // last value sent
	sent   bool       // whether last is valid
}

// newScalarVar returns a scalarVar for v if it's of a supported type
// and its current rendering, buf (parsed into lines), is just metadata
// and a single sample of name without labels. Otherwise it returns nil.
func newScalarVar(v expvar.Var, name string, buf []byte, lines []lineSpan) *scalarVar {
	switch v.(type) {
	case *expvar.Int, *syncs.ShardedInt, *expvar.Float, expvar.Func:
	default:
		return nil
	}
	if len(lines) == 0 {
		return nil
	}
	sample := lines[len(lines)-1]
	if sample.kind != lineSample || string(sample.key(buf)) != name {
		return nil
	}
	for _, ln := range lines[:len(lines)-1] {
		if ln.kind != lineMeta {
			return nil
		}
	}
	return &scalarVar{
		v:      v,
		meta:   bytes.Clone(buf[:sample.start]),
		prefix: bytes.Clone(buf[sample.start : sample.keyEnd+1]),
	}
}

func (s *scalarVar) appendFrame(dst []byte, full bool, _ selector) []byte {
	n, ok := readNumber(s.v)
	if !ok || (s.sent && !full && n == s.last) {
		return dst
	}
	if full || !s.sent {
		dst = append(dst, s.meta...)
	}
	s.last, s.sent = n, true
	dst = append(dst, s.prefix...)
	dst = n.appendTo(dst)
	return append(dst, '\n')
}

// number is a metric value, stored without formatting.
type number struct {
	kind numberKind
	bits uint64 // the int64, uint64, or IEEE 754 bits of the value
}

type numberKind uint8

const (
	numberInt numberKind = iota + 1
	numberUint
	numberFloat32
	numberFloat64
)

// readNumber reads the current value of v, a var accepted by
// newScalarVar. It reports false if v is a func that returned a
// non-numeric value.
func readNumber(v expvar.Var) (number, bool) {
	switch v := v.(type) {
	case *expvar.Int:
		return number{numberInt, uint64(v.Value())}, true
	case *syncs.ShardedInt:
		return number{numberInt, uint64(v.Value())}, true
	case *expvar.Float:
		return number{numberFloat64, math.Float64bits(v.Value())}, true
	case expvar.Func:
		switch x := v().(type) {
		case int:
			return number{numberInt, uint64(x)}, true
		case int8:
			return number{numberInt, uint64(x)}, true
		case int16:
			return number{numberInt, uint64(x)}, true
		case int32:
			return number{numberInt, uint64(x)}, true
		case int64:
			return number{numberInt, uint64(x)}, true
		case uint:
			return number{numberUint, uint64(x)}, true
		case uint8:
			return number{numberUint, uint64(x)}, true
		case uint16:
			return number{numberUint, uint64(x)}, true
		case uint32:
			return number{numberUint, uint64(x)}, true
		case uint64:
			return number{numberUint, x}, true
		case uintptr:
			return number{numberUint, uint64(x)}, true
		case float32:
			return number{numberFloat32, uint64(math.Float32bits(x))}, true
		case float64:
			return number{numberFloat64, math.Float64bits(x)}, true
		}
	}
	return number{}, false
}

// appendTo appends n to dst, formatted as fmt's %v verb would, and
// returns the extended slice.
func (n number) appendTo(dst []byte) []byte {
	switch n.kind {
	case numberInt:
		return strconv.AppendInt(dst, int64(n.bits), 10)
	case numberUint:
		return strconv.AppendUint(dst, n.bits, 10)
	case numberFloat32:
		return strconv.AppendFloat(dst, float64(math.Float32frombits(uint32(n.bits))), 'g', -1, 32)
	case numberFloat64:
		return strconv.AppendFloat(dst, math.Float64frombits(n.bits), 'g', -1, 64)
	}
	return dst
}

// commentVar is a var that renders only comments, such as a var with
// no Prometheus type. Its comments appear only in full, unfiltered
// frames.
type commentVar []byte

func (c commentVar) appendFrame(dst []byte, full bool, sel selector) []byte {
	if full && sel.all() {
		dst = append(dst, c...)
	}
	return dst
}

// renderedVar is a var, or the Go runtime metrics, rendered in full
// each frame and compared with its previous rendering.
type renderedVar struct {
	render func(io.Writer)
	w      appendWriter // w.b holds the current rendering
	lines  []lineSpan   // of w.b

	prev      []byte     // previous rendering
	prevLines []lineSpan // of prev

	fresh  bool // w.b holds a rendering from build not yet used
	synced bool // whether appendAll has run, making the include fields valid

	// sentFamilies are the metric families whose metadata has been
	// sent since the last full frame. It's usually short.
	sentFamilies []string
}

func (r *renderedVar) appendFrame(dst []byte, full bool, sel selector) []byte {
	if r.fresh {
		r.fresh = false
	} else {
		r.prev, r.w.b = r.w.b, r.prev[:0]
		r.prevLines, r.lines = r.lines, r.prevLines[:0]
		r.render(&r.w)
		r.w.b = ensureNewline(r.w.b)
		if r.synced && !full && bytes.Equal(r.w.b, r.prev) {
			r.prev, r.w.b = r.w.b, r.prev
			r.prevLines, r.lines = r.lines, r.prevLines
			return dst
		}
		r.lines = parseLines(r.lines, r.w.b)
	}
	if !r.synced || full || !sameLayout(r.w.b, r.lines, r.prev, r.prevLines) {
		return r.appendAll(dst, full, sel)
	}
	for i := range r.lines {
		ln, p := &r.lines[i], &r.prevLines[i]
		ln.include = p.include
		if ln.include && !bytes.Equal(ln.value(r.w.b), p.value(r.prev)) {
			dst = append(dst, ln.text(r.w.b)...)
		}
	}
	return dst
}

// appendAll appends every line of r's current rendering that sel
// matches, along with metadata not yet sent, and sets the lines'
// include fields. If full and sel selects everything, it also appends
// comments.
func (r *renderedVar) appendAll(dst []byte, full bool, sel selector) []byte {
	r.synced = true
	if full {
		r.sentFamilies = r.sentFamilies[:0]
	}
	b := r.w.b
	var lastName []byte // most recent sample name matched
	var lastMatch bool  // whether lastName matched
	fam, famMatch := -1, false
	for i := range r.lines {
		ln := &r.lines[i]
		switch ln.kind {
		case lineComment:
			if full && sel.all() {
				dst = append(dst, ln.text(b)...)
			}
		case lineSample:
			if name := ln.name(b); lastName == nil || !bytes.Equal(name, lastName) {
				lastName, lastMatch = name, sel.matches(name)
			}
			ln.include = lastMatch
			if !ln.include && ln.family >= 0 {
				if ln.family != fam {
					fam, famMatch = ln.family, sel.matches(r.lines[ln.family].name(b))
				}
				ln.include = famMatch
			}
			if !ln.include {
				continue
			}
			if ln.family >= 0 {
				dst = r.appendMeta(dst, ln.family)
			}
			dst = append(dst, ln.text(b)...)
		}
	}
	return dst
}

// appendMeta appends the metadata lines of the metric family whose
// first metadata line is r.lines[first], unless they were already sent.
func (r *renderedVar) appendMeta(dst []byte, first int) []byte {
	b := r.w.b
	fam := r.lines[first].name(b)
	for _, s := range r.sentFamilies {
		if s == string(fam) {
			return dst
		}
	}
	r.sentFamilies = append(r.sentFamilies, string(fam))
	for _, ln := range r.lines[first:] {
		if ln.kind != lineMeta || !bytes.Equal(ln.name(b), fam) {
			break
		}
		dst = append(dst, ln.text(b)...)
	}
	return dst
}

// sameLayout reports whether renderings a and b (parsed into aLines
// and bLines) have the same lines, other than sample values.
func sameLayout(a []byte, aLines []lineSpan, b []byte, bLines []lineSpan) bool {
	if len(aLines) != len(bLines) {
		return false
	}
	for i := range aLines {
		al, bl := &aLines[i], &bLines[i]
		if al.kind != bl.kind {
			return false
		}
		if al.kind == lineSample {
			if !bytes.Equal(al.key(a), bl.key(b)) {
				return false
			}
		} else if !bytes.Equal(al.text(a), bl.text(b)) {
			return false
		}
	}
	return true
}

// appendWriter is an [io.Writer] that appends to b.
type appendWriter struct{ b []byte }

func (w *appendWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

func ensureNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}
	return b
}

type lineKind uint8

const (
	lineComment lineKind = iota // comment other than metadata, or unparseable line
	lineMeta                    // "# TYPE", "# HELP", or "# UNIT" line
	lineSample
)

// lineSpan is a line of a Prometheus exposition, by its offsets into
// the buffer holding it.
type lineSpan struct {
	start, end         int // bounds of the line, including its newline
	nameStart, nameEnd int // bounds of the metric name, for samples and metadata
	keyEnd             int // end of the series key (name and labels), for samples
	family             int // for samples, index of the first metadata line of their family, or -1
	kind               lineKind
	include            bool // for samples, whether the line is selected
}

func (ln *lineSpan) text(b []byte) []byte  { return b[ln.start:ln.end] }
func (ln *lineSpan) name(b []byte) []byte  { return b[ln.nameStart:ln.nameEnd] }
func (ln *lineSpan) key(b []byte) []byte   { return b[ln.start:ln.keyEnd] }
func (ln *lineSpan) value(b []byte) []byte { return b[ln.keyEnd+1 : ln.end-1] }

// parseLines appends the non-blank lines of b, which must end in a
// newline if non-empty, to dst and returns the extended slice.
func parseLines(dst []lineSpan, b []byte) []lineSpan {
	fam := -1 // index in dst of the current family's first metadata line
	var famType []byte
	for start := 0; start < len(b); {
		end := start + bytes.IndexByte(b[start:], '\n') + 1
		line := b[start : end-1]
		ls := lineSpan{start: start, end: end, family: -1}
		switch {
		case len(line) == 0:
			start = end
			continue
		case line[0] == '#':
			isType, ns, ne, rest, ok := parseMetadata(line)
			if !ok {
				ls.kind = lineComment
				break
			}
			ls.kind = lineMeta
			ls.nameStart, ls.nameEnd = start+ns, start+ne
			if fam < 0 || !bytes.Equal(ls.name(b), dst[fam].name(b)) {
				fam, famType = len(dst), nil
			}
			if isType {
				famType = rest
			}
		default:
			sp := bytes.LastIndexByte(line, ' ')
			if sp <= 0 {
				ls.kind = lineComment
				break
			}
			ls.kind = lineSample
			ls.keyEnd = start + sp
			ne := bytes.IndexByte(line[:sp], '{')
			if ne < 0 {
				ne = sp
			}
			ls.nameStart, ls.nameEnd = start, start+ne
			if fam >= 0 && inFamily(ls.name(b), dst[fam].name(b), famType) {
				ls.family = fam
			} else {
				fam = -1
			}
		}
		dst = append(dst, ls)
		start = end
	}
	return dst
}

// inFamily reports whether a sample with metric name belongs to the
// metric family fam of type typ.
func inFamily(name, fam, typ []byte) bool {
	if bytes.Equal(name, fam) {
		return true
	}
	switch string(typ) {
	case "histogram", "summary":
		rest, ok := bytes.CutPrefix(name, fam)
		if !ok {
			return false
		}
		switch string(rest) {
		case "_bucket", "_sum", "_count":
			return true
		}
	}
	return false
}

// parseMetadata parses a metadata comment line ("# TYPE name type",
// "# HELP name text", or "# UNIT name unit") without its trailing
// newline. It returns the offsets of the metric name and the text
// after it.
func parseMetadata(line []byte) (isType bool, nameStart, nameEnd int, rest []byte, ok bool) {
	after, ok := bytes.CutPrefix(line, []byte("# "))
	if !ok {
		return false, 0, 0, nil, false
	}
	kind, _, ok := bytes.Cut(after, []byte(" "))
	if !ok {
		return false, 0, 0, nil, false
	}
	switch string(kind) {
	case "TYPE":
		isType = true
	case "HELP", "UNIT":
	default:
		return false, 0, 0, nil, false
	}
	nameStart = len("# ") + len(kind) + 1
	nameEnd = len(line)
	if i := bytes.IndexByte(line[nameStart:], ' '); i >= 0 {
		nameEnd = nameStart + i
		rest = line[nameEnd+1:]
	}
	if nameEnd == nameStart {
		return false, 0, 0, nil, false
	}
	return isType, nameStart, nameEnd, rest, true
}

// anyMatch reports whether sel matches the name of any sample or
// metadata line in b.
func anyMatch(b []byte, lines []lineSpan, sel selector) bool {
	for i := range lines {
		ln := &lines[i]
		if ln.kind != lineComment && sel.matches(ln.name(b)) {
			return true
		}
	}
	return false
}

// hasSeries reports whether lines include any samples or metadata.
func hasSeries(lines []lineSpan) bool {
	for _, ln := range lines {
		if ln.kind != lineComment {
			return true
		}
	}
	return false
}

// Frame is one frame of a streaming /debug/varz response, as read by
// [ReadStream].
type Frame struct {
	// Time is the server's clock when it built the frame.
	Time time.Time

	// Full is whether the frame holds every matching series, in which
	// case it replaces the client's state. Otherwise the frame holds
	// only the series whose values changed since the previous frame.
	Full bool

	// Samples maps each series, the metric name plus its labels if
	// any (such as `foo` or `foo{bar="baz"}`), to its value.
	Samples map[string]float64
}

// ReadStream reads a streaming /debug/varz response from r, calling f
// with each complete frame. Each call gets a new Frame.
//
// It returns nil when r reaches EOF between frames,
// [io.ErrUnexpectedEOF] if r ends mid-frame, or the first error from r,
// from parsing, or from f.
//
// # Stream format
//
// [Handler] and [ExpvarDoHandler] accept two optional query parameters:
//
//   - "match" is a Go regexp, and may be repeated. A sample is included if
//     any pattern matches its exposed metric name (such as "tlb_choose_local",
//     not "counter_tlb_choose_local"), or the name of its metric family (the
//     name in its "# TYPE" line, so "^foo$" matches the "foo_bucket",
//     "foo_sum" and "foo_count" samples of histogram "foo"). Without a match
//     parameter, everything is included. With one, comments other than
//     metadata ("# TYPE", "# HELP", "# UNIT") are omitted. There may be at
//     most 32 patterns.
//   - "interval" is a Go duration that turns on streaming at that interval,
//     clamped to between 100ms and 1m. Without it, the response is a single
//     exposition, as usual.
//
// A stream is a series of frames, one per interval, each like:
//
//	# TIME 2026-11-24T18:03:01.000123456Z full
//	# TYPE tlb_choose_local counter
//	tlb_choose_local 1234
//	# EOF
//
// followed by a blank line. The "# TIME" line has the server's clock when
// it built the frame and whether the frame is "full" or a "delta". The
// first frame is full, with every matching series. Later frames are deltas
// with the sample lines whose values changed since the previous frame (and
// sometimes unchanged ones, such as the other series of a LabelMap that
// gained a key); a delta with no samples serves as a heartbeat. A client
// should merge a delta into its state, should apply a
// frame only after reading its "# EOF" line, should treat a full frame as
// replacing its state, and should reconnect if it hasn't seen an "# EOF" in
// several intervals.
//
// ReadStream has no timeouts of its own. To detect a stalled server, a
// client reading an HTTP response body can cancel the request's context
// from a timer that its callback resets on every frame, which works
// because the server sends a frame every interval even when nothing
// changed:
//
//	ctx, cancel := context.WithCancel(ctx)
//	defer cancel()
//	wd := time.AfterFunc(3*interval, cancel)
//	defer wd.Stop()
//	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
//	...
//	err = varz.ReadStream(res.Body, func(f *varz.Frame) error {
//		wd.Reset(3 * interval)
//		...
//	})
//
// Don't set [http.Client.Timeout] for streams, as it limits the whole
// response, not each read.
//
// A metric family's metadata lines appear once per stream, just before its
// first sample. Other comments appear only in full frames. Series that
// disappear are not reported, as with Prometheus scrapes.
//
// A stream ends when the client goes away or the server's connection is
// closed. Each stream holds the latest values of all its series in memory,
// so clients streaming a server with high metric cardinality should use
// match. At most 16 streams may be open at once per process.
//
// A stream renders every var once when it starts, to find those that
// might match, and after that reads only those. It reads plain counters
// and gauges without formatting them unless they changed, and renders
// other vars each interval, comparing the output with the previous
// rendering. Every 10 seconds it counts the server's vars (including
// metrics.Set members), and if the count changed, it looks for new vars
// to include.
func ReadStream(r io.Reader, f func(*Frame) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 1<<20)
	var fr *Frame
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "# TIME "); ok {
			if fr != nil {
				return errors.New("varz stream: frame without # EOF")
			}
			ts, kind, _ := strings.Cut(rest, " ")
			t, err := time.Parse(time.RFC3339Nano, ts)
			if err != nil {
				return fmt.Errorf("varz stream: bad frame time: %v", err)
			}
			if kind != "full" && kind != "delta" {
				return fmt.Errorf("varz stream: bad frame kind %q", kind)
			}
			fr = &Frame{Time: t, Full: kind == "full", Samples: map[string]float64{}}
			continue
		}
		if line == "# EOF" {
			if fr == nil {
				return errors.New("varz stream: # EOF outside frame")
			}
			if err := f(fr); err != nil {
				return err
			}
			fr = nil
			continue
		}
		if line[0] == '#' {
			continue
		}
		if fr == nil {
			return errors.New("varz stream: sample outside frame")
		}
		sp := strings.LastIndexByte(line, ' ')
		if sp <= 0 {
			return fmt.Errorf("varz stream: malformed sample line %q", line)
		}
		v, err := strconv.ParseFloat(line[sp+1:], 64)
		if err != nil {
			return fmt.Errorf("varz stream: bad sample value in %q", line)
		}
		fr.Samples[line[:sp]] = v
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if fr != nil {
		return io.ErrUnexpectedEOF
	}
	return nil
}
