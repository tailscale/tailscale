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
	"tailscale.com/testy"
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

func TestStdHandler(t *testing.T) {
	var (
		handlerCode = func(code int) Handler {
			return HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(code)
				return nil
			})
		}
		handlerErr = func(code int, err error) Handler {
			return HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
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
		clock = testy.Clock{
			Start: time.Now(),
			Step:  time.Second,
		}
	)
	// cancel()

	tests := []struct {
		name     string
		h        Handler
		r        *http.Request
		wantCode int
		wantLog  Msg
	}{
		{
			name:     "handler returns 200",
			h:        handlerCode(200),
			r:        req(bgCtx, "http://example.com/"),
			wantCode: 200,
			wantLog: Msg{
				Where:    "http",
				When:     clock.Start,
				Duration: time.Second,
				HTTP: &MsgHTTP{
					Code: 200,
					Path: "/",
				},
			},
		},

		{
			name:     "handler returns 404",
			h:        handlerCode(404),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 404,
			wantLog: Msg{
				Where:    "http",
				When:     clock.Start,
				Duration: time.Second,
				HTTP: &MsgHTTP{
					Code: 404,
					Path: "/foo",
				},
			},
		},

		{
			name:     "handler returns 404 via HTTPError",
			h:        handlerErr(0, Error(404, "not found", testErr)),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 404,
			wantLog: Msg{
				Where:    "http",
				When:     clock.Start,
				Duration: time.Second,
				Msg:      "not found",
				Err:      testErr,
				HTTP: &MsgHTTP{
					Code: 404,
					Path: "/foo",
				},
			},
		},

		{
			name:     "handler returns generic error",
			h:        handlerErr(0, testErr),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 500,
			wantLog: Msg{
				Where:    "http",
				When:     clock.Start,
				Duration: time.Second,
				Msg:      "internal server error",
				Err:      testErr,
				HTTP: &MsgHTTP{
					Code: 500,
					Path: "/foo",
				},
			},
		},

		{
			name:     "handler returns error after writing response",
			h:        handlerErr(200, testErr),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 200,
			wantLog: Msg{
				Where:    "http",
				When:     clock.Start,
				Duration: time.Second,
				Err:      testErr,
				HTTP: &MsgHTTP{
					Code: 200,
					Path: "/foo",
				},
			},
		},

		{
			name:     "handler returns HTTPError after writing response",
			h:        handlerErr(200, Error(404, "not found", testErr)),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 200,
			wantLog: Msg{
				Where:    "http",
				When:     clock.Start,
				Duration: time.Second,
				Err:      testErr,
				HTTP: &MsgHTTP{
					Code: 200,
					Path: "/foo",
				},
			},
		},

		{
			name:     "handler does nothing",
			h:        HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil }),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 500,
			wantLog: Msg{
				Where:    "http",
				When:     clock.Start,
				Duration: time.Second,
				Msg:      "internal server error",
				Err:      errors.New("[unexpected] handler did not respond to the client"),
				HTTP: &MsgHTTP{
					Code: 500,
					Path: "/foo",
				},
			},
		},

		{
			name: "handler hijacks conn",
			h: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				_, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("couldn't hijack: %v", err)
				}
				return err
			}),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 0,
			wantLog: Msg{
				Where:    "http",
				When:     clock.Start,
				Duration: time.Second,
				HTTP: &MsgHTTP{
					Code: 101,
					Path: "/foo",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs []Msg
			logf := func(fmt string, args ...interface{}) {
				if fmt == "%s" {
					logs = append(logs, args[0].(Msg))
				}
				t.Logf(fmt, args...)
			}

			clock.Reset()

			rec := noopHijacker{httptest.NewRecorder(), false}
			// ResponseRecorder defaults Code to 200, grump.
			rec.Code = 0
			h := stdHandler(test.h, logf, clock.Now)
			h.ServeHTTP(&rec, test.r)
			if rec.Code != test.wantCode {
				t.Errorf("HTTP code = %v, want %v", rec.Code, test.wantCode)
			}
			if !rec.hijacked && !rec.Flushed {
				t.Errorf("handler didn't flush")
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
