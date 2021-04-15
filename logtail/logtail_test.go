// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logtail

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFastShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	testServ := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {}))
	defer testServ.Close()

	l := NewLogger(Config{
		BaseURL: testServ.URL,
	}, t.Logf)
	err := l.Shutdown(ctx)
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
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Error("failed to read HTTP request")
			}
			ts.uploaded <- body
		}))

	t.Cleanup(ts.srv.Close)

	l := NewLogger(Config{BaseURL: ts.srv.URL}, t.Logf)

	// There is always an initial "logtail started" message
	body := <-ts.uploaded
	if !strings.Contains(string(body), "started") {
		t.Errorf("unknown start logging statement: %q", string(body))
	}

	return &ts, l
}

func TestDrainPendingMessages(t *testing.T) {
	ts, l := NewLogtailTestHarness(t)

	for i := 0; i < logLines; i++ {
		l.Write([]byte("log line"))
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

	err := l.Shutdown(context.Background())
	if err != nil {
		t.Error(err)
	}
}

func TestEncodeAndUploadMessages(t *testing.T) {
	ts, l := NewLogtailTestHarness(t)

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
			`{"text": "log line"}`,
			"log line",
		},
	}

	for _, tt := range tests {
		io.WriteString(l, tt.log)
		body := <-ts.uploaded

		data := make(map[string]interface{})
		err := json.Unmarshal(body, &data)
		if err != nil {
			t.Error(err)
		}

		got := data["text"]
		if got != tt.want {
			t.Errorf("%s: got %q; want %q", tt.name, got.(string), tt.want)
		}

		ltail, ok := data["logtail"]
		if ok {
			logtailmap := ltail.(map[string]interface{})
			_, ok = logtailmap["client_time"]
			if !ok {
				t.Errorf("%s: no client_time present", tt.name)
			}
		} else {
			t.Errorf("%s: no logtail map present", tt.name)
		}
	}

	err := l.Shutdown(context.Background())
	if err != nil {
		t.Error(err)
	}
}

func TestEncodeSpecialCases(t *testing.T) {
	ts, l := NewLogtailTestHarness(t)

	// -------------------------------------------------------------------------

	// JSON log message already contains a logtail field.
	io.WriteString(l, `{"logtail": "LOGTAIL", "text": "text"}`)
	body := <-ts.uploaded
	data := make(map[string]interface{})
	err := json.Unmarshal(body, &data)
	if err != nil {
		t.Error(err)
	}
	errorHasLogtail, ok := data["error_has_logtail"]
	if ok {
		if errorHasLogtail != "LOGTAIL" {
			t.Errorf("error_has_logtail: got:%q; want:%q",
				errorHasLogtail, "LOGTAIL")
		}
	} else {
		t.Errorf("no error_has_logtail field: %v", data)
	}

	// -------------------------------------------------------------------------

	// special characters
	io.WriteString(l, "\b\f\n\r\t"+`"\`)
	bodytext := string(<-ts.uploaded)
	// json.Unmarshal would unescape the characters, we have to look at the encoded text
	escaped := strings.Contains(bodytext, `\b\f\n\r\t\"\`)
	if !escaped {
		t.Errorf("special characters got %s", bodytext)
	}

	// -------------------------------------------------------------------------

	// skipClientTime to omit the logtail metadata
	l.skipClientTime = true
	io.WriteString(l, "text")
	body = <-ts.uploaded
	data = make(map[string]interface{})
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error(err)
	}
	_, ok = data["logtail"]
	if ok {
		t.Errorf("skipClientTime: unexpected logtail map present: %v", data)
	}

	// -------------------------------------------------------------------------

	// lowMem + long string
	l.skipClientTime = false
	l.lowMem = true
	longStr := strings.Repeat("0", 512)
	io.WriteString(l, longStr)
	body = <-ts.uploaded
	data = make(map[string]interface{})
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error(err)
	}
	text, ok := data["text"]
	if !ok {
		t.Errorf("lowMem: no text %v", data)
	}
	if n := len(text.(string)); n > 300 {
		t.Errorf("lowMem: got %d chars; want <300 chars", n)
	}

	// -------------------------------------------------------------------------

	err = l.Shutdown(context.Background())
	if err != nil {
		t.Error(err)
	}
}

var sink []byte

func TestLoggerEncodeTextAllocs(t *testing.T) {
	lg := &Logger{timeNow: time.Now}
	inBuf := []byte("some text to encode")
	n := testing.AllocsPerRun(1000, func() {
		sink = lg.encodeText(inBuf, false)
	})
	if int(n) != 1 {
		t.Logf("allocs = %d; want 1", int(n))
	}
}

func TestLoggerWriteLength(t *testing.T) {
	lg := &Logger{
		timeNow: time.Now,
		buffer:  NewMemoryBuffer(1024),
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

func TestPublicIDUnmarshalText(t *testing.T) {
	const hexStr = "6c60a9e0e7af57170bb1347b2d477e4cbc27d4571a4923b21651456f931e3d55"
	x := []byte(hexStr)

	var id PublicID
	if err := id.UnmarshalText(x); err != nil {
		t.Fatal(err)
	}
	if id.String() != hexStr {
		t.Errorf("String = %q; want %q", id.String(), hexStr)
	}

	n := int(testing.AllocsPerRun(1000, func() {
		var id PublicID
		if err := id.UnmarshalText(x); err != nil {
			t.Fatal(err)
		}
	}))
	if n != 0 {
		t.Errorf("allocs = %v; want 0", n)
	}
}
