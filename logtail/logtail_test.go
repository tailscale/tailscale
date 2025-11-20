// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logtail

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/must"
)

func TestFastShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	testServ := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {}))
	defer testServ.Close()

	logger := NewLogger(Config{
		BaseURL: testServ.URL,
		Bus:     eventbustest.NewBus(t),
	}, t.Logf)
	err := logger.Shutdown(ctx)
	if err != nil {
		t.Error(err)
	}
}

// maximum number of times a test will call l.Write()
const logLines = 3

type LogtailTestServer struct {
	srv      *httptest.Server // Log server
	uploaded chan []byte
}

func NewLogtailTestHarness(t *testing.T) (*LogtailTestServer, *Logger) {
	ts := LogtailTestServer{}

	// max channel backlog = 1 "started" + #logLines x "log line" + 1 "closed"
	ts.uploaded = make(chan []byte, 2+logLines)

	ts.srv = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error("failed to read HTTP request")
			}
			ts.uploaded <- body
		}))

	t.Cleanup(ts.srv.Close)

	logger := NewLogger(Config{
		BaseURL: ts.srv.URL,
		Bus:     eventbustest.NewBus(t),
	}, t.Logf)

	// There is always an initial "logtail started" message
	body := <-ts.uploaded
	if !strings.Contains(string(body), "started") {
		t.Errorf("unknown start logging statement: %q", string(body))
	}

	return &ts, logger
}

func TestDrainPendingMessages(t *testing.T) {
	ts, logger := NewLogtailTestHarness(t)

	for range logLines {
		logger.Write([]byte("log line"))
	}

	// all of the "log line" messages usually arrive at once, but poll if needed.
	body := ""
	for i := 0; i <= logLines; i++ {
		body += string(<-ts.uploaded)
		count := strings.Count(body, "log line")
		if count == logLines {
			break
		}
		// if we never find count == logLines, the test will eventually time out.
	}

	err := logger.Shutdown(context.Background())
	if err != nil {
		t.Error(err)
	}
}

func TestEncodeAndUploadMessages(t *testing.T) {
	ts, logger := NewLogtailTestHarness(t)

	tests := []struct {
		name string
		log  string
		want string
	}{
		{
			"plain text",
			"log line",
			"log line",
		},
		{
			"simple JSON",
			`{"text":"log line"}`,
			"log line",
		},
	}

	for _, tt := range tests {
		io.WriteString(logger, tt.log)
		body := <-ts.uploaded

		data := unmarshalOne(t, body)
		got := data["text"]
		if got != tt.want {
			t.Errorf("%s: got %q; want %q", tt.name, got.(string), tt.want)
		}

		ltail, ok := data["logtail"]
		if ok {
			logtailmap := ltail.(map[string]any)
			_, ok = logtailmap["client_time"]
			if !ok {
				t.Errorf("%s: no client_time present", tt.name)
			}
		} else {
			t.Errorf("%s: no logtail map present", tt.name)
		}
	}

	err := logger.Shutdown(context.Background())
	if err != nil {
		t.Error(err)
	}
}

func TestLoggerWriteLength(t *testing.T) {
	lg := &Logger{
		clock:  tstime.StdClock{},
		buffer: NewMemoryBuffer(1024),
	}
	inBuf := []byte("some text to encode")
	n, err := lg.Write(inBuf)
	if err != nil {
		t.Error(err)
	}
	if n != len(inBuf) {
		t.Errorf("logger.Write wrote %d bytes, expected %d", n, len(inBuf))
	}
}

func TestParseAndRemoveLogLevel(t *testing.T) {
	tests := []struct {
		log       string
		wantLevel int
		wantLog   string
	}{
		{
			"no level",
			0,
			"no level",
		},
		{
			"[v1] level 1",
			1,
			"level 1",
		},
		{
			"level 1 [v1] ",
			1,
			"level 1 ",
		},
		{
			"[v2] level 2",
			2,
			"level 2",
		},
		{
			"level [v2] 2",
			2,
			"level 2",
		},
		{
			"[v3] no level 3",
			0,
			"[v3] no level 3",
		},
		{
			"some ignored text then [v\x00JSON]5{\"foo\":1234}",
			5,
			`{"foo":1234}`,
		},
	}

	for _, tt := range tests {
		gotLevel, gotLog := parseAndRemoveLogLevel([]byte(tt.log))
		if gotLevel != tt.wantLevel {
			t.Errorf("parseAndRemoveLogLevel(%q): got:%d; want %d",
				tt.log, gotLevel, tt.wantLevel)
		}
		if string(gotLog) != tt.wantLog {
			t.Errorf("parseAndRemoveLogLevel(%q): got:%q; want %q",
				tt.log, gotLog, tt.wantLog)
		}
	}
}

func unmarshalOne(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var entries []map[string]any
	err := json.Unmarshal(body, &entries)
	if err != nil {
		t.Error(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(entries))
	}
	return entries[0]
}

type simpleMemBuf struct {
	Buffer
	buf bytes.Buffer
}

func (b *simpleMemBuf) Write(p []byte) (n int, err error) { return b.buf.Write(p) }

func TestEncode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{
			"normal",
			`{"logtail":{"client_time":"1970-01-01T00:02:03.000000456Z","proc_id":7,"proc_seq":1},"text":"normal"}` + "\n",
		},
		{
			"and a [v1] level one",
			`{"logtail":{"client_time":"1970-01-01T00:02:03.000000456Z","proc_id":7,"proc_seq":1},"v":1,"text":"and a level one"}` + "\n",
		},
		{
			"[v2] some verbose two",
			`{"logtail":{"client_time":"1970-01-01T00:02:03.000000456Z","proc_id":7,"proc_seq":1},"v":2,"text":"some verbose two"}` + "\n",
		},
		{
			"{}",
			`{"logtail":{"client_time":"1970-01-01T00:02:03.000000456Z","proc_id":7,"proc_seq":1}}` + "\n",
		},
		{
			`{"foo":"bar"}`,
			`{"logtail":{"client_time":"1970-01-01T00:02:03.000000456Z","proc_id":7,"proc_seq":1},"foo":"bar"}` + "\n",
		},
		{
			"foo: [v\x00JSON]0{\"foo\":1}",
			"{\"logtail\":{\"client_time\":\"1970-01-01T00:02:03.000000456Z\",\"proc_id\":7,\"proc_seq\":1},\"foo\":1}\n",
		},
		{
			"foo: [v\x00JSON]2{\"foo\":1}",
			"{\"logtail\":{\"client_time\":\"1970-01-01T00:02:03.000000456Z\",\"proc_id\":7,\"proc_seq\":1},\"v\":2,\"foo\":1}\n",
		},
	}
	for _, tt := range tests {
		buf := new(simpleMemBuf)
		lg := &Logger{
			clock:        tstest.NewClock(tstest.ClockOpts{Start: time.Unix(123, 456).UTC()}),
			buffer:       buf,
			procID:       7,
			procSequence: 1,
		}
		io.WriteString(lg, tt.in)
		got := buf.buf.String()
		if got != tt.want {
			t.Errorf("for %q,\n got: %#q\nwant: %#q\n", tt.in, got, tt.want)
		}
		if err := json.Compact(new(bytes.Buffer), buf.buf.Bytes()); err != nil {
			t.Errorf("invalid output JSON for %q: %s", tt.in, got)
		}
	}
}

// Test that even if Logger.Write modifies the input buffer, we still return the
// length of the input buffer, not what we shrank it down to. Otherwise the
// caller will think we did a short write, violating the io.Writer contract.
func TestLoggerWriteResult(t *testing.T) {
	buf := NewMemoryBuffer(100)
	lg := &Logger{
		clock:  tstest.NewClock(tstest.ClockOpts{Start: time.Unix(123, 0)}),
		buffer: buf,
	}

	const in = "[v1] foo"
	n, err := lg.Write([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := n, len(in); got != want {
		t.Errorf("Write = %v; want %v", got, want)
	}
	back, err := buf.TryReadLine()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(back), `{"logtail":{"client_time":"1970-01-01T00:02:03Z"},"v":1,"text":"foo"}`+"\n"; got != want {
		t.Errorf("mismatch.\n got: %#q\nwant: %#q", back, want)
	}
}

func TestAppendMetadata(t *testing.T) {
	var lg Logger
	lg.clock = tstest.NewClock(tstest.ClockOpts{Start: time.Date(2000, 01, 01, 0, 0, 0, 0, time.UTC)})
	lg.metricsDelta = func() string { return "metrics" }

	for _, tt := range []struct {
		skipClientTime bool
		skipMetrics    bool
		procID         uint32
		procSeq        uint64
		errDetail      string
		errData        jsontext.Value
		level          int
		want           string
	}{
		{want: `"logtail":{"client_time":"2000-01-01T00:00:00Z"},"metrics":"metrics",`},
		{skipClientTime: true, want: `"metrics":"metrics",`},
		{skipMetrics: true, want: `"logtail":{"client_time":"2000-01-01T00:00:00Z"},`},
		{skipClientTime: true, skipMetrics: true, want: ``},
		{skipClientTime: true, skipMetrics: true, procID: 1, want: `"logtail":{"proc_id":1},`},
		{skipClientTime: true, skipMetrics: true, procSeq: 2, want: `"logtail":{"proc_seq":2},`},
		{skipClientTime: true, skipMetrics: true, procID: 1, procSeq: 2, want: `"logtail":{"proc_id":1,"proc_seq":2},`},
		{skipMetrics: true, procID: 1, procSeq: 2, want: `"logtail":{"client_time":"2000-01-01T00:00:00Z","proc_id":1,"proc_seq":2},`},
		{skipClientTime: true, skipMetrics: true, errDetail: "error", want: `"logtail":{"error":{"detail":"error"}},`},
		{skipClientTime: true, skipMetrics: true, errData: jsontext.Value("null"), want: `"logtail":{"error":{"bad_data":null}},`},
		{skipClientTime: true, skipMetrics: true, level: 5, want: `"v":5,`},
		{procID: 1, procSeq: 2, errDetail: "error", errData: jsontext.Value(`["something","bad","happened"]`), level: 2,
			want: `"logtail":{"client_time":"2000-01-01T00:00:00Z","proc_id":1,"proc_seq":2,"error":{"detail":"error","bad_data":["something","bad","happened"]}},"metrics":"metrics","v":2,`},
	} {
		got := string(lg.appendMetadata(nil, tt.skipClientTime, tt.skipMetrics, tt.procID, tt.procSeq, tt.errDetail, tt.errData, tt.level))
		if got != tt.want {
			t.Errorf("appendMetadata(%v, %v, %v, %v, %v, %v, %v):\n\tgot  %s\n\twant %s", tt.skipClientTime, tt.skipMetrics, tt.procID, tt.procSeq, tt.errDetail, tt.errData, tt.level, got, tt.want)
		}
		gotObj := "{" + strings.TrimSuffix(got, ",") + "}"
		if !jsontext.Value(gotObj).IsValid() {
			t.Errorf("`%s`.IsValid() = false, want true", gotObj)
		}
	}
}

func TestAppendText(t *testing.T) {
	var lg Logger
	lg.clock = tstest.NewClock(tstest.ClockOpts{Start: time.Date(2000, 01, 01, 0, 0, 0, 0, time.UTC)})
	lg.metricsDelta = func() string { return "metrics" }
	lg.lowMem = true

	for _, tt := range []struct {
		text           string
		skipClientTime bool
		procID         uint32
		procSeq        uint64
		level          int
		want           string
	}{
		{want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z"},"metrics":"metrics"}`},
		{skipClientTime: true, want: `{"metrics":"metrics"}`},
		{skipClientTime: true, procID: 1, procSeq: 2, want: `{"logtail":{"proc_id":1,"proc_seq":2},"metrics":"metrics"}`},
		{text: "fizz buzz", want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z"},"metrics":"metrics","text":"fizz buzz"}`},
		{text: "\b\f\n\r\t\"\\", want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z"},"metrics":"metrics","text":"\b\f\n\r\t\"\\"}`},
		{text: "x" + strings.Repeat("😐", maxSize), want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z"},"metrics":"metrics","text":"x` + strings.Repeat("😐", 1023) + `…+1044484"}`},
	} {
		got := string(lg.appendText(nil, []byte(tt.text), tt.skipClientTime, tt.procID, tt.procSeq, tt.level))
		if !strings.HasSuffix(got, "\n") {
			t.Errorf("`%s` does not end with a newline", got)
		}
		got = got[:len(got)-1]
		if got != tt.want {
			t.Errorf("appendText(%v, %v, %v, %v, %v):\n\tgot  %s\n\twant %s", tt.text[:min(len(tt.text), 256)], tt.skipClientTime, tt.procID, tt.procSeq, tt.level, got, tt.want)
		}
		if !jsontext.Value(got).IsValid() {
			t.Errorf("`%s`.IsValid() = false, want true", got)
		}
	}
}

func TestAppendTextOrJSON(t *testing.T) {
	var lg Logger
	lg.clock = tstest.NewClock(tstest.ClockOpts{Start: time.Date(2000, 01, 01, 0, 0, 0, 0, time.UTC)})
	lg.metricsDelta = func() string { return "metrics" }
	lg.lowMem = true

	for _, tt := range []struct {
		in    string
		level int
		want  string
	}{
		{want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z"},"metrics":"metrics"}`},
		{in: "[]", want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z"},"metrics":"metrics","text":"[]"}`},
		{level: 1, want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z"},"metrics":"metrics","v":1}`},
		{in: `{}`, want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z"}}`},
		{in: `{}{}`, want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z"},"metrics":"metrics","text":"{}{}"}`},
		{in: "{\n\"fizz\"\n:\n\"buzz\"\n}", want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z"},"fizz":"buzz"}`},
		{in: `{ "logtail" : "duplicate" }`, want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z","error":{"detail":"duplicate logtail member","bad_data":"duplicate"}}}`},
		{in: `{ "fizz" : "buzz" , "logtail" : "duplicate" }`, want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z","error":{"detail":"duplicate logtail member","bad_data":"duplicate"}}, "fizz" : "buzz"}`},
		{in: `{ "logtail" : "duplicate" , "fizz" : "buzz" }`, want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z","error":{"detail":"duplicate logtail member","bad_data":"duplicate"}} , "fizz" : "buzz"}`},
		{in: `{ "fizz" : "buzz" , "logtail" : "duplicate" , "wizz" : "wuzz" }`, want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z","error":{"detail":"duplicate logtail member","bad_data":"duplicate"}}, "fizz" : "buzz" , "wizz" : "wuzz"}`},
		{in: `{"long":"` + strings.Repeat("a", maxSize) + `"}`, want: `{"logtail":{"client_time":"2000-01-01T00:00:00Z","error":{"detail":"entry too large: 262155 bytes","bad_data":"{\"long\":\"` + strings.Repeat("a", 43681) + `…+218465"}}}`},
	} {
		got := string(lg.appendTextOrJSONLocked(nil, []byte(tt.in), tt.level))
		if !strings.HasSuffix(got, "\n") {
			t.Errorf("`%s` does not end with a newline", got)
		}
		got = got[:len(got)-1]
		if got != tt.want {
			t.Errorf("appendTextOrJSON(%v, %v):\n\tgot  %s\n\twant %s", tt.in[:min(len(tt.in), 256)], tt.level, got, tt.want)
		}
		if !jsontext.Value(got).IsValid() {
			t.Errorf("`%s`.IsValid() = false, want true", got)
		}
	}
}

var sink []byte

func TestAppendTextAllocs(t *testing.T) {
	lg := &Logger{clock: tstime.StdClock{}}
	inBuf := []byte("some text to encode")
	procID := uint32(0x24d32ee9)
	procSequence := uint64(0x12346)
	must.Do(tstest.MinAllocsPerRun(t, 0, func() {
		sink = lg.appendText(sink[:0], inBuf, false, procID, procSequence, 0)
	}))
}

func TestAppendJSONAllocs(t *testing.T) {
	lg := &Logger{clock: tstime.StdClock{}}
	inBuf := []byte(`{"fizz":"buzz"}`)
	must.Do(tstest.MinAllocsPerRun(t, 1, func() {
		sink = lg.appendTextOrJSONLocked(sink[:0], inBuf, 0)
	}))
}

type discardBuffer struct{ Buffer }

func (discardBuffer) Write(p []byte) (n int, err error) { return n, nil }

var testdataTextLog = []byte(`netcheck: report: udp=true v6=false v6os=true mapvarydest=false hair=false portmap= v4a=174.xxx.xxx.xxx:18168 derp=2 derpdist=1v4:82ms,2v4:18ms,3v4:214ms,4v4:171ms,5v4:196ms,7v4:124ms,8v4:149ms,9v4:56ms,10v4:32ms,11v4:196ms,12v4:71ms,13v4:48ms,14v4:166ms,16v4:85ms,17v4:25ms,18v4:153ms,19v4:176ms,20v4:193ms,21v4:84ms,22v4:182ms,24v4:73ms`)
var testdataJSONLog = []byte(`{"end":"2024-04-08T21:39:15.715291586Z","nodeId":"nQRJBE7CNTRL","physicalTraffic":[{"dst":"127.x.x.x:2","src":"100.x.x.x:0","txBytes":148,"txPkts":1},{"dst":"127.x.x.x:2","src":"100.x.x.x:0","txBytes":148,"txPkts":1},{"dst":"98.x.x.x:1025","rxBytes":640,"rxPkts":5,"src":"100.x.x.x:0","txBytes":640,"txPkts":5},{"dst":"24.x.x.x:49973","rxBytes":640,"rxPkts":5,"src":"100.x.x.x:0","txBytes":640,"txPkts":5},{"dst":"73.x.x.x:41641","rxBytes":732,"rxPkts":6,"src":"100.x.x.x:0","txBytes":820,"txPkts":7},{"dst":"75.x.x.x:1025","rxBytes":640,"rxPkts":5,"src":"100.x.x.x:0","txBytes":640,"txPkts":5},{"dst":"75.x.x.x:41641","rxBytes":640,"rxPkts":5,"src":"100.x.x.x:0","txBytes":640,"txPkts":5},{"dst":"174.x.x.x:35497","rxBytes":13008,"rxPkts":98,"src":"100.x.x.x:0","txBytes":26688,"txPkts":150},{"dst":"47.x.x.x:41641","rxBytes":640,"rxPkts":5,"src":"100.x.x.x:0","txBytes":640,"txPkts":5},{"dst":"64.x.x.x:41641","rxBytes":640,"rxPkts":5,"src":"100.x.x.x:0","txBytes":640,"txPkts":5}],"start":"2024-04-08T21:39:11.099495616Z","virtualTraffic":[{"dst":"100.x.x.x:33008","proto":6,"src":"100.x.x.x:22","txBytes":1260,"txPkts":10},{"dst":"100.x.x.x:0","proto":1,"rxBytes":420,"rxPkts":5,"src":"100.x.x.x:0","txBytes":420,"txPkts":5},{"dst":"100.x.x.x:32984","proto":6,"src":"100.x.x.x:22","txBytes":1340,"txPkts":10},{"dst":"100.x.x.x:32998","proto":6,"src":"100.x.x.x:22","txBytes":1020,"txPkts":10},{"dst":"100.x.x.x:32994","proto":6,"src":"100.x.x.x:22","txBytes":1260,"txPkts":10},{"dst":"100.x.x.x:32980","proto":6,"src":"100.x.x.x:22","txBytes":1260,"txPkts":10},{"dst":"100.x.x.x:0","proto":1,"rxBytes":420,"rxPkts":5,"src":"100.x.x.x:0","txBytes":420,"txPkts":5},{"dst":"100.x.x.x:0","proto":1,"rxBytes":420,"rxPkts":5,"src":"100.x.x.x:0","txBytes":420,"txPkts":5},{"dst":"100.x.x.x:32950","proto":6,"src":"100.x.x.x:22","txBytes":1340,"txPkts":10},{"dst":"100.x.x.x:22","proto":6,"src":"100.x.x.x:53332","txBytes":60,"txPkts":1},{"dst":"100.x.x.x:0","proto":1,"src":"100.x.x.x:0","txBytes":420,"txPkts":5},{"dst":"100.x.x.x:0","proto":1,"rxBytes":420,"rxPkts":5,"src":"100.x.x.x:0","txBytes":420,"txPkts":5},{"dst":"100.x.x.x:32966","proto":6,"src":"100.x.x.x:22","txBytes":1260,"txPkts":10},{"dst":"100.x.x.x:22","proto":6,"src":"100.x.x.x:57882","txBytes":60,"txPkts":1},{"dst":"100.x.x.x:22","proto":6,"src":"100.x.x.x:53326","txBytes":60,"txPkts":1},{"dst":"100.x.x.x:22","proto":6,"src":"100.x.x.x:57892","txBytes":60,"txPkts":1},{"dst":"100.x.x.x:32934","proto":6,"src":"100.x.x.x:22","txBytes":8712,"txPkts":55},{"dst":"100.x.x.x:0","proto":1,"rxBytes":420,"rxPkts":5,"src":"100.x.x.x:0","txBytes":420,"txPkts":5},{"dst":"100.x.x.x:32942","proto":6,"src":"100.x.x.x:22","txBytes":1260,"txPkts":10},{"dst":"100.x.x.x:0","proto":1,"rxBytes":420,"rxPkts":5,"src":"100.x.x.x:0","txBytes":420,"txPkts":5},{"dst":"100.x.x.x:32964","proto":6,"src":"100.x.x.x:22","txBytes":1260,"txPkts":10},{"dst":"100.x.x.x:0","proto":1,"rxBytes":420,"rxPkts":5,"src":"100.x.x.x:0","txBytes":420,"txPkts":5},{"dst":"100.x.x.x:0","proto":1,"rxBytes":420,"rxPkts":5,"src":"100.x.x.x:0","txBytes":420,"txPkts":5},{"dst":"100.x.x.x:22","proto":6,"src":"100.x.x.x:37238","txBytes":60,"txPkts":1},{"dst":"100.x.x.x:22","proto":6,"src":"100.x.x.x:37252","txBytes":60,"txPkts":1}]}`)

func BenchmarkWriteText(b *testing.B) {
	var lg Logger
	lg.clock = tstime.StdClock{}
	lg.buffer = discardBuffer{}
	b.ReportAllocs()
	for range b.N {
		must.Get(lg.Write(testdataTextLog))
	}
}

func BenchmarkWriteJSON(b *testing.B) {
	var lg Logger
	lg.clock = tstime.StdClock{}
	lg.buffer = discardBuffer{}
	b.ReportAllocs()
	for range b.N {
		must.Get(lg.Write(testdataJSONLog))
	}
}
