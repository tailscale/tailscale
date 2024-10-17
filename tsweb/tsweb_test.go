// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsweb

import (
	"bufio"
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/metrics"
	"tailscale.com/tstest"
	"tailscale.com/util/httpm"
	"tailscale.com/util/must"
	"tailscale.com/util/vizerror"
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
	const exampleRequestID = "example-request-id"
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
			return httptest.NewRequest("GET", url, nil).WithContext(ctx)
		}

		testErr = errors.New("test error")
		bgCtx   = context.Background()
		// canceledCtx, cancel = context.WithCancel(bgCtx)
		startTime = time.Unix(1687870000, 1234)
	)
	// cancel()

	tests := []struct {
		name       string
		rh         ReturnHandler
		r          *http.Request
		errHandler ErrorHandlerFunc
		wantCode   int
		wantLog    AccessLogRecord
		wantBody   string
	}{
		{
			name:     "handler returns 200",
			rh:       handlerCode(200),
			r:        req(bgCtx, "http://example.com/"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				Time:       startTime,
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
			name:     "handler returns 200 with request ID",
			rh:       handlerCode(200),
			r:        req(bgCtx, "http://example.com/"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				Time:       startTime,
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
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Code:       404,
			},
		},

		{
			name:     "handler returns 404 with request ID",
			rh:       handlerCode(404),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 404,
			wantLog: AccessLogRecord{
				Time:       startTime,
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
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "not found: " + testErr.Error(),
				Code:       404,
			},
			wantBody: "not found\n",
		},

		{
			name:     "handler returns 404 via HTTPError with request ID",
			rh:       handlerErr(0, Error(404, "not found", testErr)),
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/foo"),
			wantCode: 404,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "not found: " + testErr.Error(),
				Code:       404,
				RequestID:  exampleRequestID,
			},
			wantBody: "not found\n" + exampleRequestID + "\n",
		},

		{
			name:     "handler returns 404 with nil child error",
			rh:       handlerErr(0, Error(404, "not found", nil)),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 404,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "not found",
				Code:       404,
			},
			wantBody: "not found\n",
		},

		{
			name:     "handler returns 404 with request ID and nil child error",
			rh:       handlerErr(0, Error(404, "not found", nil)),
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/foo"),
			wantCode: 404,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "not found",
				Code:       404,
				RequestID:  exampleRequestID,
			},
			wantBody: "not found\n" + exampleRequestID + "\n",
		},

		{
			name:     "handler returns user-visible error",
			rh:       handlerErr(0, vizerror.New("visible error")),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 500,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "visible error",
				Code:       500,
			},
			wantBody: "visible error\n",
		},

		{
			name:     "handler returns user-visible error with request ID",
			rh:       handlerErr(0, vizerror.New("visible error")),
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/foo"),
			wantCode: 500,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "visible error",
				Code:       500,
				RequestID:  exampleRequestID,
			},
			wantBody: "visible error\n" + exampleRequestID + "\n",
		},

		{
			name:     "handler returns user-visible error wrapped by private error",
			rh:       handlerErr(0, fmt.Errorf("private internal error: %w", vizerror.New("visible error"))),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 500,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "visible error",
				Code:       500,
			},
			wantBody: "visible error\n",
		},

		{
			name: "handler returns JSON-formatted HTTPError",
			rh: ReturnHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				h := Error(http.StatusBadRequest, `{"isjson": true}`, errors.New("uh"))
				h.Header = http.Header{"Content-Type": {"application/json"}}
				return h
			}),
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/foo"),
			wantCode: 400,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        `{"isjson": true}: uh`,
				Code:       400,
				RequestID:  exampleRequestID,
			},
			wantBody: `{"isjson": true}`,
		},

		{
			name:     "handler returns user-visible error wrapped by private error with request ID",
			rh:       handlerErr(0, fmt.Errorf("private internal error: %w", vizerror.New("visible error"))),
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/foo"),
			wantCode: 500,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        "visible error",
				Code:       500,
				RequestID:  exampleRequestID,
			},
			wantBody: "visible error\n" + exampleRequestID + "\n",
		},

		{
			name:     "handler returns generic error",
			rh:       handlerErr(0, testErr),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 500,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        testErr.Error(),
				Code:       500,
			},
			wantBody: "Internal Server Error\n",
		},

		{
			name:     "handler returns generic error with request ID",
			rh:       handlerErr(0, testErr),
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/foo"),
			wantCode: 500,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        testErr.Error(),
				Code:       500,
				RequestID:  exampleRequestID,
			},
			wantBody: "Internal Server Error\n" + exampleRequestID + "\n",
		},

		{
			name:     "handler returns error after writing response",
			rh:       handlerErr(200, testErr),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				Time:       startTime,
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
			name:     "handler returns error after writing response with request ID",
			rh:       handlerErr(200, testErr),
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/foo"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        testErr.Error(),
				Code:       200,
				RequestID:  exampleRequestID,
			},
		},

		{
			name:     "handler returns HTTPError after writing response",
			rh:       handlerErr(200, Error(404, "not found", testErr)),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				Time:       startTime,
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
				Time:       startTime,
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
				Time:    startTime,
				Seconds: 1.0,

				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Code:       101,
			},
		},

		{
			name:     "error handler gets run",
			rh:       handlerErr(0, Error(404, "not found", nil)), // status code changed in errHandler
			r:        req(bgCtx, "http://example.com/"),
			wantCode: 200,
			errHandler: func(w http.ResponseWriter, r *http.Request, e HTTPError) {
				http.Error(w, e.Msg, 200)
			},
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				TLS:        false,
				Host:       "example.com",
				Method:     "GET",
				Code:       200,
				Err:        "not found",
				RequestURI: "/",
			},
			wantBody: "not found\n",
		},

		{
			name:     "error handler gets run with request ID",
			rh:       handlerErr(0, Error(404, "not found", nil)), // status code changed in errHandler
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/"),
			wantCode: 200,
			errHandler: func(w http.ResponseWriter, r *http.Request, e HTTPError) {
				requestID := RequestIDFromContext(r.Context())
				http.Error(w, fmt.Sprintf("%s with request ID %s", e.Msg, requestID), 200)
			},
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				TLS:        false,
				Host:       "example.com",
				Method:     "GET",
				Code:       200,
				Err:        "not found",
				RequestURI: "/",
				RequestID:  exampleRequestID,
			},
			wantBody: "not found with request ID " + exampleRequestID + "\n",
		},

		{
			name:     "inner_cancelled",
			rh:       handlerErr(0, context.Canceled), // return canceled error, but the request was not cancelled
			r:        req(bgCtx, "http://example.com/"),
			wantCode: 500,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				TLS:        false,
				Host:       "example.com",
				Method:     "GET",
				Code:       500,
				Err:        "context canceled",
				RequestURI: "/",
			},
			wantBody: "Internal Server Error\n",
		},

		{
			name: "nested",
			rh: ReturnHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				// Here we completely handle the web response with an
				// independent StdHandler that is unaware of the outer
				// StdHandler and its logger.
				StdHandler(ReturnHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					return Error(501, "Not Implemented", errors.New("uhoh"))
				}), HandlerOptions{
					OnError: func(w http.ResponseWriter, r *http.Request, h HTTPError) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(h.Code)
						fmt.Fprintf(w, `{"error": %q}`, h.Msg)
					},
				}).ServeHTTP(w, r)
				return nil
			}),
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/"),
			wantCode: 501,
			wantLog: AccessLogRecord{
				Time:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				TLS:        false,
				Host:       "example.com",
				Method:     "GET",
				Code:       501,
				Err:        "Not Implemented: uhoh",
				RequestURI: "/",
				RequestID:  exampleRequestID,
			},
			wantBody: `{"error": "Not Implemented"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := tstest.NewClock(tstest.ClockOpts{
				Start: startTime,
				Step:  time.Second,
			})

			// Callbacks to track the emitted AccessLogRecords.
			var (
				logs   []AccessLogRecord
				starts []AccessLogRecord
				comps  []AccessLogRecord
			)
			logf := func(fmt string, args ...any) {
				if fmt == "%s" {
					logs = append(logs, args[0].(AccessLogRecord))
				}
				t.Logf(fmt, args...)
			}
			oncomp := func(r *http.Request, msg AccessLogRecord) {
				comps = append(comps, msg)
			}
			onstart := func(r *http.Request, msg AccessLogRecord) {
				starts = append(starts, msg)
			}

			bucket := func(r *http.Request) string { return r.URL.RequestURI() }

			// Build the request handler.
			opts := HandlerOptions{
				Now: clock.Now,

				OnError:      test.errHandler,
				Logf:         logf,
				OnStart:      onstart,
				OnCompletion: oncomp,

				StatusCodeCounters:     &expvar.Map{},
				StatusCodeCountersFull: &expvar.Map{},
				BucketedStats: &BucketedStatsOptions{
					Bucket:   bucket,
					Started:  &metrics.LabelMap{},
					Finished: &metrics.LabelMap{},
				},
			}
			h := StdHandler(test.rh, opts)

			// Pre-create the BucketedStats.{Started,Finished} metric for the
			// test request's bucket so that even non-200 status codes get
			// recorded immediately. logHandler tries to avoid counting unknown
			// paths, so here we're marking them known.
			opts.BucketedStats.Started.Get(bucket(test.r))
			opts.BucketedStats.Finished.Get(bucket(test.r))

			// Perform the request.
			rec := noopHijacker{httptest.NewRecorder(), false}
			h.ServeHTTP(&rec, test.r)

			// Validate the client received the expected response.
			res := rec.Result()
			if res.StatusCode != test.wantCode {
				t.Errorf("HTTP code = %v, want %v", res.StatusCode, test.wantCode)
			}
			if diff := cmp.Diff(rec.Body.String(), test.wantBody); diff != "" {
				t.Errorf("handler wrote incorrect body (-got +want):\n%s", diff)
			}

			// Fields we want to check for in tests but not repeat on every case.
			test.wantLog.RemoteAddr = "192.0.2.1:1234" // Hard-coded by httptest.NewRequest.
			test.wantLog.Bytes = len(test.wantBody)

			// Validate the AccessLogRecords written to logf and sent back to
			// the OnCompletion handler.
			checkOutput := func(src string, msgs []AccessLogRecord, opts ...cmp.Option) {
				t.Helper()
				if len(msgs) != 1 {
					t.Errorf("%s: expected 1 msg, got: %#v", src, msgs)
				} else if diff := cmp.Diff(msgs[0], test.wantLog, opts...); diff != "" {
					t.Errorf("%s: wrong access log (-got +want):\n%s", src, diff)
				}
			}
			checkOutput("hander wrote logs", logs)
			checkOutput("start msgs", starts, cmpopts.IgnoreFields(AccessLogRecord{}, "Time", "Seconds", "Code", "Err", "Bytes"))
			checkOutput("completion msgs", comps)

			// Validate the code counters.
			if got, want := opts.StatusCodeCounters.String(), fmt.Sprintf(`{"%dxx": 1}`, test.wantLog.Code/100); got != want {
				t.Errorf("StatusCodeCounters: got %s, want %s", got, want)
			}
			if got, want := opts.StatusCodeCountersFull.String(), fmt.Sprintf(`{"%d": 1}`, test.wantLog.Code); got != want {
				t.Errorf("StatusCodeCountersFull: got %s, want %s", got, want)
			}

			// Validate the bucketed counters.
			if got, want := opts.BucketedStats.Started.String(), fmt.Sprintf("{%q: 1}", bucket(test.r)); got != want {
				t.Errorf("BucketedStats.Started: got %q, want %q", got, want)
			}
			if got, want := opts.BucketedStats.Finished.String(), fmt.Sprintf("{%q: 1}", bucket(test.r)); got != want {
				t.Errorf("BucketedStats.Finished: got %s, want %s", got, want)
			}
		})
	}
}

func TestStdHandler_Panic(t *testing.T) {
	var r AccessLogRecord
	h := StdHandler(
		ReturnHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			panicElsewhere()
			return nil
		}),
		HandlerOptions{
			Logf: t.Logf,
			OnCompletion: func(_ *http.Request, alr AccessLogRecord) {
				r = alr
			},
		},
	)

	// Run our panicking handler in a http.Server which catches and rethrows
	// any panics.
	recovered := make(chan any, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			recovered <- recover()
		}()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)

	// Send a request to our server.
	res, err := http.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if rec := <-recovered; rec != nil {
		t.Fatalf("expected no panic but saw: %v", rec)
	}

	// Check that the log message contained the stack trace in the error.
	var logerr bool
	if p := "panic: panicked elsewhere\n\ngoroutine "; !strings.HasPrefix(r.Err, p) {
		t.Errorf("got Err prefix %q, want %q", r.Err[:min(len(r.Err), len(p))], p)
		logerr = true
	}
	if s := "\ntailscale.com/tsweb.panicElsewhere("; !strings.Contains(r.Err, s) {
		t.Errorf("want Err substr %q, not found", s)
		logerr = true
	}
	if logerr {
		t.Logf("logger got error: (quoted) %q\n\n(verbatim)\n%s", r.Err, r.Err)
	}

	// Check that the server sent an error response.
	if res.StatusCode != 500 {
		t.Errorf("got status code %d, want %d", res.StatusCode, 500)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("error reading body: %s", err)
	} else if want := "Internal Server Error\n"; string(body) != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	res.Body.Close()
}

func TestStdHandler_Canceled(t *testing.T) {
	now := time.Now()

	r := make(chan AccessLogRecord)
	var e *HTTPError
	handlerOpen := make(chan struct{})
	h := StdHandler(
		ReturnHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			close(handlerOpen)
			ctx := r.Context()
			<-ctx.Done()
			w.WriteHeader(200) // Ignored.
			return ctx.Err()
		}),
		HandlerOptions{
			Logf: t.Logf,
			Now:  func() time.Time { return now },
			OnError: func(w http.ResponseWriter, r *http.Request, h HTTPError) {
				e = &h
			},
			OnCompletion: func(_ *http.Request, alr AccessLogRecord) {
				r <- alr
			},
		},
	)
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)

	// Create a context which gets canceled after the handler starts processing
	// the request.
	ctx, cancelReq := context.WithCancel(context.Background())
	go func() {
		<-handlerOpen
		cancelReq()
	}()

	// Send a request to our server.
	req, err := http.NewRequestWithContext(ctx, httpm.GET, s.URL, nil)
	if err != nil {
		t.Fatalf("making request: %s", err)
	}
	res, err := http.DefaultClient.Do(req)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, want context.Canceled", err)
	}
	if res != nil {
		t.Errorf("got response %#v, want nil", res)
	}

	// Check that we got the expected log record.
	got := <-r
	got.Seconds = 0
	got.RemoteAddr = ""
	got.Host = ""
	got.UserAgent = ""
	want := AccessLogRecord{
		Time:       now,
		Code:       499,
		Method:     "GET",
		Err:        "context canceled",
		Proto:      "HTTP/1.1",
		RequestURI: "/",
	}
	if d := cmp.Diff(want, got); d != "" {
		t.Errorf("AccessLogRecord wrong (-want +got)\n%s", d)
	}

	// Check that we rendered no response to the client after
	// logHandler.OnCompletion has been called.
	if e != nil {
		t.Errorf("got OnError callback with %#v, want no callback", e)
	}
}

func TestStdHandler_CanceledAfterHeader(t *testing.T) {
	now := time.Now()

	r := make(chan AccessLogRecord)
	var e *HTTPError
	handlerOpen := make(chan struct{})
	h := StdHandler(
		ReturnHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusNoContent)
			close(handlerOpen)
			ctx := r.Context()
			<-ctx.Done()
			return ctx.Err()
		}),
		HandlerOptions{
			Logf: t.Logf,
			Now:  func() time.Time { return now },
			OnError: func(w http.ResponseWriter, r *http.Request, h HTTPError) {
				e = &h
			},
			OnCompletion: func(_ *http.Request, alr AccessLogRecord) {
				r <- alr
			},
		},
	)
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)

	// Create a context which gets canceled after the handler starts processing
	// the request.
	ctx, cancelReq := context.WithCancel(context.Background())
	go func() {
		<-handlerOpen
		cancelReq()
	}()

	// Send a request to our server.
	req, err := http.NewRequestWithContext(ctx, httpm.GET, s.URL, nil)
	if err != nil {
		t.Fatalf("making request: %s", err)
	}
	res, err := http.DefaultClient.Do(req)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, want context.Canceled", err)
	}
	if res != nil {
		t.Errorf("got response %#v, want nil", res)
	}

	// Check that we got the expected log record.
	got := <-r
	got.Seconds = 0
	got.RemoteAddr = ""
	got.Host = ""
	got.UserAgent = ""
	want := AccessLogRecord{
		Time:       now,
		Code:       499,
		Method:     "GET",
		Err:        "context canceled (original code 204)",
		Proto:      "HTTP/1.1",
		RequestURI: "/",
	}
	if d := cmp.Diff(want, got); d != "" {
		t.Errorf("AccessLogRecord wrong (-want +got)\n%s", d)
	}

	// Check that we rendered no response to the client after
	// logHandler.OnCompletion has been called.
	if e != nil {
		t.Errorf("got OnError callback with %#v, want no callback", e)
	}
}

func TestStdHandler_ConnectionClosedDuringBody(t *testing.T) {
	now := time.Now()

	// Start a HTTP server that writes back zeros until the request is abandoned.
	// We next put a reverse-proxy in front of this server.
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zeroes := make([]byte, 1024)
		for r.Context().Err() == nil {
			w.Write(zeroes)
		}
	}))
	defer rs.Close()

	r := make(chan AccessLogRecord)
	var e *HTTPError
	responseStarted := make(chan struct{})
	requestCanceled := make(chan struct{})

	// Create another server which proxies our zeroes server.
	// The [httputil.ReverseProxy] will panic with [http.ErrAbortHandler] when
	// it fails to copy the response to the client.
	h := StdHandler(
		ReturnHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			(&httputil.ReverseProxy{
				Director: func(r *http.Request) {
					r.URL = must.Get(url.Parse(rs.URL))
				},
			}).ServeHTTP(w, r)
			return nil
		}),
		HandlerOptions{
			Logf: t.Logf,
			Now:  func() time.Time { return now },
			OnError: func(w http.ResponseWriter, r *http.Request, h HTTPError) {
				e = &h
			},
			OnCompletion: func(_ *http.Request, alr AccessLogRecord) {
				r <- alr
			},
		},
	)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(responseStarted)
		<-requestCanceled
		h.ServeHTTP(w, r.WithContext(context.WithoutCancel(r.Context())))
	}))
	t.Cleanup(s.Close)

	// Create a context which gets canceled after the handler starts processing
	// the request.
	ctx, cancelReq := context.WithCancel(context.Background())
	go func() {
		<-responseStarted
		cancelReq()
	}()

	// Send a request to our server.
	req, err := http.NewRequestWithContext(ctx, httpm.GET, s.URL, nil)
	if err != nil {
		t.Fatalf("making request: %s", err)
	}
	res, err := http.DefaultClient.Do(req)
	close(requestCanceled)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, want context.Canceled", err)
	}
	if res != nil {
		t.Errorf("got response %#v, want nil", res)
	}

	// Check that we got the expected log record.
	got := <-r
	got.Seconds = 0
	got.RemoteAddr = ""
	got.Host = ""
	got.UserAgent = ""
	want := AccessLogRecord{
		Time:       now,
		Code:       499,
		Method:     "GET",
		Err:        "net/http: abort Handler (original code 200)",
		Proto:      "HTTP/1.1",
		RequestURI: "/",
	}
	if d := cmp.Diff(want, got, cmpopts.IgnoreFields(AccessLogRecord{}, "Bytes")); d != "" {
		t.Errorf("AccessLogRecord wrong (-want +got)\n%s", d)
	}

	// Check that we rendered no response to the client after
	// logHandler.OnCompletion has been called.
	if e != nil {
		t.Errorf("got OnError callback with %#v, want no callback", e)
	}
}

func TestStdHandler_OnErrorPanic(t *testing.T) {
	var r AccessLogRecord
	h := StdHandler(
		ReturnHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			// This response is supposed to be written by OnError, but it panics
			// so nothing is written.
			return Error(401, "lacking auth", nil)
		}),
		HandlerOptions{
			Logf: t.Logf,
			OnError: func(w http.ResponseWriter, r *http.Request, h HTTPError) {
				panicElsewhere()
			},
			OnCompletion: func(_ *http.Request, alr AccessLogRecord) {
				r = alr
			},
		},
	)

	// Run our panicking handler in a http.Server which catches and rethrows
	// any panics.
	recovered := make(chan any, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			recovered <- recover()
		}()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)

	// Send a request to our server.
	res, err := http.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if rec := <-recovered; rec != nil {
		t.Fatalf("expected no panic but saw: %v", rec)
	}

	// Check that the log message contained the stack trace in the error.
	var logerr bool
	if p := "lacking auth\n\nthen panic: panicked elsewhere\n\ngoroutine "; !strings.HasPrefix(r.Err, p) {
		t.Errorf("got Err prefix %q, want %q", r.Err[:min(len(r.Err), len(p))], p)
		logerr = true
	}
	if s := "\ntailscale.com/tsweb.panicElsewhere("; !strings.Contains(r.Err, s) {
		t.Errorf("want Err substr %q, not found", s)
		logerr = true
	}
	if logerr {
		t.Logf("logger got error: (quoted) %q\n\n(verbatim)\n%s", r.Err, r.Err)
	}

	// Check that the server sent a bare 500 response.
	if res.StatusCode != 500 {
		t.Errorf("got status code %d, want %d", res.StatusCode, 500)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("error reading body: %s", err)
	} else if want := ""; string(body) != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	res.Body.Close()
}

func TestLogHandler_QuietLogging(t *testing.T) {
	now := time.Now()
	var logs []string
	logf := func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}

	var done bool
	onComp := func(r *http.Request, alr AccessLogRecord) {
		if done {
			t.Fatal("expected only one OnCompletion call")
		}
		done = true

		want := AccessLogRecord{
			Time:       now,
			RemoteAddr: "192.0.2.1:1234",
			Proto:      "HTTP/1.1",
			Host:       "example.com",
			Method:     "GET",
			RequestURI: "/",
			Code:       200,
		}
		if diff := cmp.Diff(want, alr); diff != "" {
			t.Fatalf("unexpected OnCompletion AccessLogRecord (-want +got):\n%s", diff)
		}
	}

	LogHandler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.WriteHeader(201) // loggingResponseWriter will write a warning.
		}),
		LogOptions{
			Logf:         logf,
			OnCompletion: onComp,
			QuietLogging: true,
			Now:          func() time.Time { return now },
		},
	).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest("GET", "/", nil),
	)

	if !done {
		t.Fatal("OnCompletion call didn't happen")
	}

	wantLogs := []string{
		"[unexpected] HTTP handler set statusCode twice (200 and 201)",
	}
	if diff := cmp.Diff(wantLogs, logs); diff != "" {
		t.Fatalf("logs (-want +got):\n%s", diff)
	}
}

func TestErrorHandler_Panic(t *testing.T) {
	// errorHandler should panic when not wrapped in logHandler.
	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("expected errorHandler to panic when not wrapped in logHandler")
		}
		if want := any("uhoh"); rec != want {
			t.Fatalf("got panic %#v, want %#v", rec, want)
		}
	}()
	ErrorHandler(
		ReturnHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			panic("uhoh")
		}),
		ErrorOptions{},
	).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

func panicElsewhere() {
	panic("panicked elsewhere")
}

func BenchmarkLogNot200(b *testing.B) {
	b.ReportAllocs()
	rh := handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// Implicit 200 OK.
		return nil
	})
	h := StdHandler(rh, HandlerOptions{QuietLoggingIfSuccessful: true})
	req := httptest.NewRequest("GET", "/", nil)
	rw := new(httptest.ResponseRecorder)
	for range b.N {
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
	h := StdHandler(rh, HandlerOptions{})
	req := httptest.NewRequest("GET", "/", nil)
	rw := new(httptest.ResponseRecorder)
	for range b.N {
		*rw = httptest.ResponseRecorder{}
		h.ServeHTTP(rw, req)
	}
}

func TestHTTPError_Unwrap(t *testing.T) {
	wrappedErr := fmt.Errorf("wrapped")
	err := Error(404, "not found", wrappedErr)
	if got := errors.Unwrap(err); got != wrappedErr {
		t.Errorf("HTTPError.Unwrap() = %v, want %v", got, wrappedErr)
	}
}

func TestAcceptsEncoding(t *testing.T) {
	tests := []struct {
		in, enc string
		want    bool
	}{
		{"", "gzip", false},
		{"gzip", "gzip", true},
		{"foo,gzip", "gzip", true},
		{"foo, gzip", "gzip", true},
		{"foo, gzip ", "gzip", true},
		{"gzip, foo ", "gzip", true},
		{"gzip, foo ", "br", false},
		{"gzip, foo ", "fo", false},
		{"gzip;q=1.2, foo ", "gzip", true},
		{" gzip;q=1.2, foo ", "gzip", true},
	}
	for i, tt := range tests {
		h := make(http.Header)
		if tt.in != "" {
			h.Set("Accept-Encoding", tt.in)
		}
		got := AcceptsEncoding(&http.Request{Header: h}, tt.enc)
		if got != tt.want {
			t.Errorf("%d. got %v; want %v", i, got, tt.want)
		}
	}
}

func TestPort80Handler(t *testing.T) {
	tests := []struct {
		name    string
		h       *Port80Handler
		req     string
		wantLoc string
	}{
		{
			name:    "no_fqdn",
			h:       &Port80Handler{},
			req:     "GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n",
			wantLoc: "https://foo.com/",
		},
		{
			name:    "fqdn_and_path",
			h:       &Port80Handler{FQDN: "bar.com"},
			req:     "GET /path HTTP/1.1\r\nHost: foo.com\r\n\r\n",
			wantLoc: "https://bar.com/path",
		},
		{
			name:    "path_and_query_string",
			h:       &Port80Handler{FQDN: "baz.com"},
			req:     "GET /path?a=b HTTP/1.1\r\nHost: foo.com\r\n\r\n",
			wantLoc: "https://baz.com/path?a=b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.ReadRequest(bufio.NewReader(strings.NewReader(tt.req)))
			rec := httptest.NewRecorder()
			tt.h.ServeHTTP(rec, r)
			got := rec.Result()
			if got, want := got.StatusCode, 302; got != want {
				t.Errorf("got status code %v; want %v", got, want)
			}
			if got, want := got.Header.Get("Location"), "https://foo.com/"; got != tt.wantLoc {
				t.Errorf("Location = %q; want %q", got, want)
			}
		})
	}
}

func TestCleanRedirectURL(t *testing.T) {
	tailscaleHost := []string{"tailscale.com"}
	tailscaleAndOtherHost := []string{"microsoft.com", "tailscale.com"}
	localHost := []string{"127.0.0.1", "localhost"}
	myServer := []string{"myserver"}
	cases := []struct {
		url     string
		hosts   []string
		want    string
		wantErr bool
	}{
		{"http://tailscale.com/foo", tailscaleHost, "http://tailscale.com/foo", false},
		{"http://tailscale.com/foo", tailscaleAndOtherHost, "http://tailscale.com/foo", false},
		{"http://microsoft.com/foo", tailscaleAndOtherHost, "http://microsoft.com/foo", false},
		{"https://tailscale.com/foo", tailscaleHost, "https://tailscale.com/foo", false},
		{"/foo", tailscaleHost, "/foo", false},
		{"//tailscale.com/foo", tailscaleHost, "//tailscale.com/foo", false},
		{"/a/foobar", tailscaleHost, "/a/foobar", false},
		{"http://127.0.0.1/a/foobar", localHost, "http://127.0.0.1/a/foobar", false},
		{"http://127.0.0.1:123/a/foobar", localHost, "http://127.0.0.1:123/a/foobar", false},
		{"http://127.0.0.1:31544/a/foobar", localHost, "http://127.0.0.1:31544/a/foobar", false},
		{"http://localhost/a/foobar", localHost, "http://localhost/a/foobar", false},
		{"http://localhost:123/a/foobar", localHost, "http://localhost:123/a/foobar", false},
		{"http://localhost:31544/a/foobar", localHost, "http://localhost:31544/a/foobar", false},
		{"http://myserver/a/foobar", myServer, "http://myserver/a/foobar", false},
		{"http://myserver:123/a/foobar", myServer, "http://myserver:123/a/foobar", false},
		{"http://myserver:31544/a/foobar", myServer, "http://myserver:31544/a/foobar", false},
		{"http://evil.com/foo", tailscaleHost, "", true},
		{"//evil.com", tailscaleHost, "", true},
		{"\\\\evil.com", tailscaleHost, "", true},
		{"javascript:alert(123)", tailscaleHost, "", true},
		{"file:///", tailscaleHost, "", true},
		{"file:////SERVER/directory/goats.txt", tailscaleHost, "", true},
		{"https://google.com", tailscaleHost, "", true},
		{"", tailscaleHost, "", false},
		{"\"\"", tailscaleHost, "", true},
		{"https://tailscale.com@goats.com:8443", tailscaleHost, "", true},
		{"https://tailscale.com:8443@goats.com:8443", tailscaleHost, "", true},
		{"HttP://tailscale.com", tailscaleHost, "http://tailscale.com", false},
		{"http://TaIlScAlE.CoM/spongebob", tailscaleHost, "http://TaIlScAlE.CoM/spongebob", false},
		{"ftp://tailscale.com", tailscaleHost, "", true},
		{"https:/evil.com", tailscaleHost, "", true},                     // regression test for tailscale/corp#892
		{"%2Fa%2F44869c061701", tailscaleHost, "/a/44869c061701", false}, // regression test for tailscale/corp#13288
		{"https%3A%2Ftailscale.com", tailscaleHost, "", true},            // escaped colon-single-slash malformed URL
		{"", nil, "", false},
	}

	for _, tc := range cases {
		gotURL, err := CleanRedirectURL(tc.url, tc.hosts)
		if err != nil {
			if !tc.wantErr {
				t.Errorf("CleanRedirectURL(%q, %v) got error: %v", tc.url, tc.hosts, err)
			}
		} else {
			if tc.wantErr {
				t.Errorf("CleanRedirectURL(%q, %v) got %q, want an error", tc.url, tc.hosts, gotURL)
			}
			if got := gotURL.String(); got != tc.want {
				t.Errorf("CleanRedirectURL(%q, %v) = %q, want %q", tc.url, tc.hosts, got, tc.want)
			}
		}
	}
}

func TestBucket(t *testing.T) {
	tcs := []struct {
		path string
		want string
	}{
		{"/map", "/map"},
		{"/key?v=63", "/key"},
		{"/map/a87e865a9d1c7", "/map/…"},
		{"/machine/37fc1acb57f256b69b0d76749d814d91c68b241057c6b127fee3df37e4af111e", "/machine/…"},
		{"/machine/37fc1acb57f256b69b0d76749d814d91c68b241057c6b127fee3df37e4af111e/map", "/machine/…/map"},
		{"/api/v2/tailnet/jeremiah@squish.com/devices", "/api/v2/tailnet/…/devices"},
		{"/machine/ssh/wait/5227109621243650/to/7111899293970143/a/a9e4e04cc01b", "/machine/ssh/wait/…/to/…/a/…"},
		{"/a/831a4bf39856?refreshed=true", "/a/…"},
		{"/c2n/nxaaa1CNTRL", "/c2n/…"},
		{"/api/v2/tailnet/blueberries.com/keys/kxaDK21CNTRL", "/api/v2/tailnet/…/keys/…"},
		{"/api/v2/tailnet/bloop@passkey/devices", "/api/v2/tailnet/…/devices"},
	}

	for _, tc := range tcs {
		t.Run(tc.path, func(t *testing.T) {
			o := BucketedStatsOptions{}
			bucket := (&o).bucketForRequest(&http.Request{
				URL: must.Get(url.Parse(tc.path)),
			})

			if bucket != tc.want {
				t.Errorf("bucket for %q was %q, want %q", tc.path, bucket, tc.want)
			}
		})
	}
}

func ExampleMiddlewareStack() {
	// setHeader returns a middleware that sets header k = vs.
	setHeader := func(k string, vs ...string) Middleware {
		k = textproto.CanonicalMIMEHeaderKey(k)
		return func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header()[k] = vs
				h.ServeHTTP(w, r)
			})
		}
	}

	// h is a http.Handler which prints the A, B & C response headers, wrapped
	// in a few middleware which set those headers.
	var h http.Handler = MiddlewareStack(
		setHeader("A", "mw1"),
		MiddlewareStack(
			setHeader("A", "mw2.1"),
			setHeader("B", "mw2.2"),
			setHeader("C", "mw2.3"),
			setHeader("C", "mw2.4"),
		),
		setHeader("B", "mw3"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("A", w.Header().Get("A"))
		fmt.Println("B", w.Header().Get("B"))
		fmt.Println("C", w.Header().Get("C"))
	}))

	// Invoke the handler.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("", "/", nil))
	// Output:
	// A mw2.1
	// B mw3
	// C mw2.4
}
