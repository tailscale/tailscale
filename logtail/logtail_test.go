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
	l.Shutdown(ctx)
}

// accumulate some logs before the server becomes available, exercise the drain path
func TestDrainPendingMessages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	uploaded := make(chan int)
	bodytext := ""
	testServ := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Error("failed to read HTTP request")
			}
			bodytext += "\n" + string(body)

			uploaded <- 0
		}))
	defer testServ.Close()

	l := NewLogger(Config{BaseURL: testServ.URL}, t.Logf)
	for i := 0; i < 3; i++ {
		l.Write([]byte("log line"))
	}

	select {
	case <-uploaded:
		if strings.Count(bodytext, "log line") == 3 {
			break
		}
	case <-time.After(1 * time.Second):
		t.Errorf("Timed out waiting for log uploads")
	}

	l.Shutdown(ctx)
	cancel()
	if strings.Count(bodytext, "log line") != 3 {
		t.Errorf("got %q; want: 3 copies of %q", bodytext, "log line")
	}
}

func TestEncodeAndUploadMessages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var jsonbody []byte
	uploaded := make(chan int)
	testServ := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Error("failed to read HTTP request")
			}
			jsonbody = body
			uploaded <- 0
		}))
	defer testServ.Close()

	l := NewLogger(Config{BaseURL: testServ.URL}, t.Logf)

	// There is always an initial "logtail started" message
	<-uploaded
	if !strings.Contains(string(jsonbody), "started") {
		t.Errorf("initialize: got:%q; want:%q", string(jsonbody), "started")
	}

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
		{
			"escaped characters",
			`\b\f\n\r\t"\\`,
			`\b\f\n\r\t"\\`,
		},
	}

	for _, tt := range tests {
		io.WriteString(l, tt.log)
		<-uploaded

		data := make(map[string]interface{})
		err := json.Unmarshal(jsonbody, &data)
		if err != nil {
			t.Error(err)
		}

		got, ok := data["text"]
		if ok {
			if got != tt.want {
				t.Errorf("%s: got %q; want %q", tt.name, got.(string), tt.want)
			}
		} else {
			t.Errorf("no text in: %v", data)
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

	// test some special cases

	// JSON log message already contains a logtail field.
	io.WriteString(l, `{"logtail": "LOGTAIL", "text": "text"}`)
	<-uploaded
	data := make(map[string]interface{})
	err := json.Unmarshal(jsonbody, &data)
	if err != nil {
		t.Error(err)
	}
	error_has_logtail, ok := data["error_has_logtail"]
	if ok {
		if error_has_logtail.(string) != "LOGTAIL" {
			t.Errorf("error_has_logtail: got:%q; want:%q",
				error_has_logtail.(string), "LOGTAIL")
		}
	} else {
		t.Errorf("no error_has_logtail field: %v", data)
	}

	// skipClientTime to omit the logtail metadata
	l.skipClientTime = true
	io.WriteString(l, "text")
	<-uploaded
	data = make(map[string]interface{})
	err = json.Unmarshal(jsonbody, &data)
	if err != nil {
		t.Error(err)
	}
	_, ok = data["logtail"]
	if ok {
		t.Errorf("skipClientTime: unexpected logtail map present: %v", data)
	}

	// lowMem + long string
	l.skipClientTime = false
	l.lowMem = true
	longStr := strings.Repeat("0", 512)
	io.WriteString(l, longStr)
	<-uploaded
	data = make(map[string]interface{})
	err = json.Unmarshal(jsonbody, &data)
	if err != nil {
		t.Error(err)
	}
	text, ok := data["text"]
	if !ok {
		t.Errorf("lowMem: no text %v", data)
	}
	if len(text.(string)) > 300 {
		t.Errorf("lowMem: got %d chars; want <300 chars", len(text.(string)))
	}

	l.Shutdown(ctx)
	cancel()
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
			t.Errorf("%q: got:%d; want %d", tt.log, gotLevel, tt.wantLevel)
		}
		if string(gotLog) != tt.wantLog {
			t.Errorf("%q: got:%q; want %q", tt.log, gotLog, tt.wantLog)
		}
	}
}
