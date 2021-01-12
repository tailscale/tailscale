// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logtail

import (
	"context"
	"encoding/json"
	"fmt"
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
	uploads := 0
	uploaded := make(chan int)
	bodytext := ""
	testServ := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			uploads += 1
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Error("failed to read HTTP request")
			}
			bodytext += "\n" + string(body)

			uploaded <- 0
		}))
	defer testServ.Close()

	l := NewLogger(Config{BaseURL: testServ.URL}, t.Logf)
	for i := 0; i < 10; i++ {
		l.Write([]byte("log line"))
	}

	fmt.Println("server started")
	<-uploaded

	l.Shutdown(ctx)
	cancel()
	if uploads == 0 {
		t.Error("no log uploads")
	}
	if strings.Count(bodytext, "log line") != 10 {
		t.Errorf("want: 10 copies of \"log line\"; got: %v", bodytext)
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
		t.Errorf("initialize: want:\"started\"; got:\"%s\"", string(jsonbody))
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
			"{\"text\": \"log line\"}",
			"log line",
		},
	}

	for _, tt := range tests {
		l.Write([]byte(tt.log))
		<-uploaded

		data := make(map[string]interface{})
		err := json.Unmarshal(jsonbody, &data)
		if err != nil {
			t.Error(err)
		}

		got, ok := data["text"]
		if ok {
			if got != tt.want {
				t.Errorf("%s: want text \"%s\"; got \"%s\"",
					tt.name, tt.want, got.(string))
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
	l.Write([]byte("{\"logtail\": \"LOGTAIL\", \"text\": \"text\"}"))
	<-uploaded
	data := make(map[string]interface{})
	err := json.Unmarshal(jsonbody, &data)
	if err != nil {
		t.Error(err)
	}
	error_has_logtail, ok := data["error_has_logtail"]
	if ok {
		if error_has_logtail.(string) != "LOGTAIL" {
			t.Errorf("error_has_logtail: want:LOGTAIL; got:\"%s\"",
				error_has_logtail.(string))
		}
	} else {
		t.Errorf("no error_has_logtail field: %v", data)
	}

	// skipClientTime to omit the logtail metadata
	l.skipClientTime = true
	l.Write([]byte("text"))
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
			t.Errorf("\"%s\": got:%d; want %d", tt.log, gotLevel, tt.wantLevel)
		}
		if string(gotLog) != tt.wantLog {
			t.Errorf("\"%s\": got:\"%s\"; want \"%s\"", tt.log, gotLog, tt.wantLog)
		}
	}
}
