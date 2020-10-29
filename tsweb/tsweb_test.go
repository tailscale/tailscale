// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tstest"
)

type noopHijacker struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *noopHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	// Hijack "successfully" but don't bother returning a conn.
	h.hijacked = true
	return nil, nil, nil
}

type handlerFunc func(http.ResponseWriter, *http.Request) error

func (f handlerFunc) ServeHTTPReturn(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

func TestStdHandler(t *testing.T) {
	var (
		handlerCode = func(code int) ReturnHandler {
			return handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(code)
				return nil
			})
		}
		handlerErr = func(code int, err error) ReturnHandler {
			return handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				if code != 0 {
					w.WriteHeader(code)
				}
				return err
			})
		}

		req = func(ctx context.Context, url string) *http.Request {
			ret, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				panic(err)
			}
			return ret
		}

		testErr = errors.New("test error")
		bgCtx   = context.Background()
		// canceledCtx, cancel = context.WithCancel(bgCtx)
		clock = tstest.Clock{
			Start: time.Now(),
			Step:  time.Second,
		}
	)
	// cancel()

	tests := []struct {
		name     string
		rh       ReturnHandler
		r        *http.Request
		wantCode int
		wantLog  AccessLogRecord
	}{
		{
			name:     "handler returns 200",
			rh:       handlerCode(200),
			r:        req(bgCtx, "http://example.com/"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				When:       clock.Start,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				TLS:        false,
				Host:       "example.com",
				Method:     "GET",
				Code:       200,
				RequestURI: "/",
			},
		},

		{
			name:     "handler returns 404",
			rh:       handlerCode(404),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 404,
			wantLog: AccessLogRecord{
				When:       clock.Start,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Code:       404,
			},
		},

		{
			name:     "handler returns 404 via HTTPError",
			rh:       handlerErr(0, Error(404, "not found", testErr)),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 404,
			wantLog: AccessLogRecord{
				When:       clock.Start,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "not found: " + testErr.Error(),
				Code:       404,
			},
		},

		{
			name:     "handler returns 404 with nil child error",
			rh:       handlerErr(0, Error(404, "not found", nil)),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 404,
			wantLog: AccessLogRecord{
				When:       clock.Start,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "not found",
				Code:       404,
			},
		},

		{
			name:     "handler returns generic error",
			rh:       handlerErr(0, testErr),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 500,
			wantLog: AccessLogRecord{
				When:       clock.Start,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        testErr.Error(),
				Code:       500,
			},
		},

		{
			name:     "handler returns error after writing response",
			rh:       handlerErr(200, testErr),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				When:       clock.Start,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        testErr.Error(),
				Code:       200,
			},
		},

		{
			name:     "handler returns HTTPError after writing response",
			rh:       handlerErr(200, Error(404, "not found", testErr)),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				When:       clock.Start,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "not found: " + testErr.Error(),
				Code:       200,
			},
		},

		{
			name:     "handler does nothing",
			rh:       handlerFunc(func(http.ResponseWriter, *http.Request) error { return nil }),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				When:       clock.Start,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Code:       200,
			},
		},

		{
			name: "handler hijacks conn",
			rh: handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				_, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("couldn't hijack: %v", err)
				}
				return err
			}),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				When:    clock.Start,
				Seconds: 1.0,

				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Code:       101,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs []AccessLogRecord
			logf := func(fmt string, args ...interface{}) {
				if fmt == "%s" {
					logs = append(logs, args[0].(AccessLogRecord))
				}
				t.Logf(fmt, args...)
			}

			clock.Reset()

			rec := noopHijacker{httptest.NewRecorder(), false}
			h := StdHandlerOpts(test.rh, HandlerOptions{Logf: logf, Now: clock.Now})
			h.ServeHTTP(&rec, test.r)
			res := rec.Result()
			if res.StatusCode != test.wantCode {
				t.Errorf("HTTP code = %v, want %v", res.StatusCode, test.wantCode)
			}
			if len(logs) != 1 {
				t.Errorf("handler didn't write a request log")
				return
			}
			errTransform := cmp.Transformer("err", func(e error) string {
				if e == nil {
					return ""
				}
				return e.Error()
			})
			if diff := cmp.Diff(logs[0], test.wantLog, errTransform); diff != "" {
				t.Errorf("handler wrote incorrect request log (-got+want):\n%s", diff)
			}
		})
	}
}

func BenchmarkLogNot200(b *testing.B) {
	b.ReportAllocs()
	rh := handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// Implicit 200 OK.
		return nil
	})
	discardLogger := func(string, ...interface{}) {}
	h := StdHandlerNo200s(rh, discardLogger)
	req := httptest.NewRequest("GET", "/", nil)
	rw := new(httptest.ResponseRecorder)
	for i := 0; i < b.N; i++ {
		*rw = httptest.ResponseRecorder{}
		h.ServeHTTP(rw, req)
	}
}

func BenchmarkLog(b *testing.B) {
	b.ReportAllocs()
	rh := handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// Implicit 200 OK.
		return nil
	})
	discardLogger := func(string, ...interface{}) {}
	h := StdHandler(rh, discardLogger)
	req := httptest.NewRequest("GET", "/", nil)
	rw := new(httptest.ResponseRecorder)
	for i := 0; i < b.N; i++ {
		*rw = httptest.ResponseRecorder{}
		h.ServeHTTP(rw, req)
	}
}
