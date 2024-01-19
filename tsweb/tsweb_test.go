// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsweb

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tstest"
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
			ret, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				panic(err)
			}
			return ret
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
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
			name:     "handler returns user-visible error wrapped by private error with request ID",
			rh:       handlerErr(0, fmt.Errorf("private internal error: %w", vizerror.New("visible error"))),
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/foo"),
			wantCode: 500,
			wantLog: AccessLogRecord{
				When:       startTime,
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
				When:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        testErr.Error(),
				Code:       500,
			},
			wantBody: "internal server error\n",
		},

		{
			name:     "handler returns generic error with request ID",
			rh:       handlerErr(0, testErr),
			r:        req(RequestIDKey.WithValue(bgCtx, exampleRequestID), "http://example.com/foo"),
			wantCode: 500,
			wantLog: AccessLogRecord{
				When:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				Host:       "example.com",
				Method:     "GET",
				RequestURI: "/foo",
				Err:        testErr.Error(),
				Code:       500,
				RequestID:  exampleRequestID,
			},
			wantBody: "internal server error\n" + exampleRequestID + "\n",
		},

		{
			name:     "handler returns error after writing response",
			rh:       handlerErr(200, testErr),
			r:        req(bgCtx, "http://example.com/foo"),
			wantCode: 200,
			wantLog: AccessLogRecord{
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
				When:       startTime,
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
				When:    startTime,
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
				When:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				TLS:        false,
				Host:       "example.com",
				Method:     "GET",
				Code:       404,
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
				When:       startTime,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				TLS:        false,
				Host:       "example.com",
				Method:     "GET",
				Code:       404,
				Err:        "not found",
				RequestURI: "/",
				RequestID:  exampleRequestID,
			},
			wantBody: "not found with request ID " + exampleRequestID + "\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs []AccessLogRecord
			logf := func(fmt string, args ...any) {
				if fmt == "%s" {
					logs = append(logs, args[0].(AccessLogRecord))
				}
				t.Logf(fmt, args...)
			}

			clock := tstest.NewClock(tstest.ClockOpts{
				Start: startTime,
				Step:  time.Second,
			})

			rec := noopHijacker{httptest.NewRecorder(), false}
			h := StdHandler(test.rh, HandlerOptions{Logf: logf, Now: clock.Now, OnError: test.errHandler})
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
			if diff := cmp.Diff(rec.Body.String(), test.wantBody); diff != "" {
				t.Errorf("handler wrote incorrect body (-got+want):\n%s", diff)
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
	h := StdHandler(rh, HandlerOptions{QuietLoggingIfSuccessful: true})
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
	h := StdHandler(rh, HandlerOptions{})
	req := httptest.NewRequest("GET", "/", nil)
	rw := new(httptest.ResponseRecorder)
	for i := 0; i < b.N; i++ {
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
		url   string
		hosts []string
		want  string
	}{
		{"http://tailscale.com/foo", tailscaleHost, "http://tailscale.com/foo"},
		{"http://tailscale.com/foo", tailscaleAndOtherHost, "http://tailscale.com/foo"},
		{"http://microsoft.com/foo", tailscaleAndOtherHost, "http://microsoft.com/foo"},
		{"https://tailscale.com/foo", tailscaleHost, "https://tailscale.com/foo"},
		{"/foo", tailscaleHost, "/foo"},
		{"//tailscale.com/foo", tailscaleHost, "//tailscale.com/foo"},

		{"/a/foobar", tailscaleHost, "/a/foobar"},
		{"http://127.0.0.1/a/foobar", localHost, "http://127.0.0.1/a/foobar"},
		{"http://127.0.0.1:123/a/foobar", localHost, "http://127.0.0.1:123/a/foobar"},
		{"http://127.0.0.1:31544/a/foobar", localHost, "http://127.0.0.1:31544/a/foobar"},
		{"http://localhost/a/foobar", localHost, "http://localhost/a/foobar"},
		{"http://localhost:123/a/foobar", localHost, "http://localhost:123/a/foobar"},
		{"http://localhost:31544/a/foobar", localHost, "http://localhost:31544/a/foobar"},
		{"http://myserver/a/foobar", myServer, "http://myserver/a/foobar"},
		{"http://myserver:123/a/foobar", myServer, "http://myserver:123/a/foobar"},
		{"http://myserver:31544/a/foobar", myServer, "http://myserver:31544/a/foobar"},
		{"http://evil.com/foo", tailscaleHost, ""},
		{"//evil.com", tailscaleHost, ""},
		{"HttP://tailscale.com", tailscaleHost, "http://tailscale.com"},
		{"http://TaIlScAlE.CoM/spongebob", tailscaleHost, "http://TaIlScAlE.CoM/spongebob"},
		{"ftp://tailscale.com", tailscaleHost, ""},
		{"https:/evil.com", tailscaleHost, ""},                    // regression test for tailscale/corp#892
		{"%2Fa%2F44869c061701", tailscaleHost, "/a/44869c061701"}, // regression test for tailscale/corp#13288
		{"https%3A%2Ftailscale.com", tailscaleHost, ""},           // escaped colon-single-slash malformed URL
	}

	for _, tc := range cases {
		gotURL, err := CleanRedirectURL(tc.url, tc.hosts)
		if err != nil {
			if tc.want != "" {
				t.Errorf("CleanRedirectURL(%q, %v) got error: %v", tc.url, tc.hosts, err)
			}
		} else {
			if got := gotURL.String(); got != tc.want {
				t.Errorf("CleanRedirectURL(%q, %v) = %q, want %q", tc.url, tc.hosts, got, tc.want)
			}
		}
	}
}
