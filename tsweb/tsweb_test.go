// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/metrics"
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
		name       string
		rh         ReturnHandler
		r          *http.Request
		errHandler ErrorHandlerFunc
		wantCode   int
		wantLog    AccessLogRecord
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
		{
			name:     "error handler gets run",
			rh:       handlerErr(0, Error(404, "not found", nil)), // status code changed in errHandler
			r:        req(bgCtx, "http://example.com/"),
			wantCode: 200,
			errHandler: func(w http.ResponseWriter, r *http.Request, e HTTPError) {
				http.Error(w, e.Msg, 200)
			},
			wantLog: AccessLogRecord{
				When:       clock.Start,
				Seconds:    1.0,
				Proto:      "HTTP/1.1",
				TLS:        false,
				Host:       "example.com",
				Method:     "GET",
				Code:       404,
				Err:        "not found",
				RequestURI: "/",
			},
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

			clock.Reset()

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

func TestVarzHandler(t *testing.T) {
	t.Run("globals_log", func(t *testing.T) {
		rec := httptest.NewRecorder()
		VarzHandler(rec, httptest.NewRequest("GET", "/", nil))
		t.Logf("Got: %s", rec.Body.Bytes())
	})

	half := new(expvar.Float)
	half.Set(0.5)

	tests := []struct {
		name string
		k    string // key name
		v    expvar.Var
		want string
	}{
		{
			"int",
			"foo",
			new(expvar.Int),
			"# TYPE foo counter\nfoo 0\n",
		},
		{
			"int_with_type_counter",
			"counter_foo",
			new(expvar.Int),
			"# TYPE foo counter\nfoo 0\n",
		},
		{
			"int_with_type_gauge",
			"gauge_foo",
			new(expvar.Int),
			"# TYPE foo gauge\nfoo 0\n",
		},
		{
			// For a float = 0.0, Prometheus client_golang outputs "0"
			"float_zero",
			"foo",
			new(expvar.Float),
			"# TYPE foo gauge\nfoo 0\n",
		},
		{
			"float_point_5",
			"foo",
			half,
			"# TYPE foo gauge\nfoo 0.5\n",
		},
		{
			"float_with_type_counter",
			"counter_foo",
			half,
			"# TYPE foo counter\nfoo 0.5\n",
		},
		{
			"float_with_type_gauge",
			"gauge_foo",
			half,
			"# TYPE foo gauge\nfoo 0.5\n",
		},
		{
			"metrics_set",
			"s",
			&metrics.Set{
				Map: *(func() *expvar.Map {
					m := new(expvar.Map)
					m.Init()
					m.Add("foo", 1)
					m.Add("bar", 2)
					return m
				})(),
			},
			"# TYPE s_bar counter\ns_bar 2\n# TYPE s_foo counter\ns_foo 1\n",
		},
		{
			"metrics_set_TODO_gauge_type",
			"gauge_s", // TODO(bradfitz): arguably a bug; should pass down type
			&metrics.Set{
				Map: *(func() *expvar.Map {
					m := new(expvar.Map)
					m.Init()
					m.Add("foo", 1)
					m.Add("bar", 2)
					return m
				})(),
			},
			"# TYPE s_bar counter\ns_bar 2\n# TYPE s_foo counter\ns_foo 1\n",
		},
		{
			"expvar_map_untyped",
			"api_status_code",
			func() *expvar.Map {
				m := new(expvar.Map)
				m.Init()
				m.Add("2xx", 100)
				m.Add("5xx", 2)
				return m
			}(),
			"api_status_code_2xx 100\napi_status_code_5xx 2\n",
		},
		{
			"func_float64",
			"counter_x",
			expvar.Func(func() any { return float64(1.2) }),
			"# TYPE x counter\nx 1.2\n",
		},
		{
			"func_float64_gauge",
			"gauge_x",
			expvar.Func(func() any { return float64(1.2) }),
			"# TYPE x gauge\nx 1.2\n",
		},
		{
			"func_float64_untyped",
			"x",
			expvar.Func(func() any { return float64(1.2) }),
			"x 1.2\n",
		},
		{
			"metrics_label_map",
			"counter_m",
			&metrics.LabelMap{
				Label: "label",
				Map: *(func() *expvar.Map {
					m := new(expvar.Map)
					m.Init()
					m.Add("foo", 1)
					m.Add("bar", 2)
					return m
				})(),
			},
			"# TYPE m counter\nm{label=\"bar\"} 2\nm{label=\"foo\"} 1\n",
		},
		{
			"metrics_label_map_untyped",
			"control_save_config",
			(func() *metrics.LabelMap {
				m := &metrics.LabelMap{Label: "reason"}
				m.Add("new", 1)
				m.Add("updated", 1)
				m.Add("fun", 1)
				return m
			})(),
			"control_save_config{reason=\"fun\"} 1\ncontrol_save_config{reason=\"new\"} 1\ncontrol_save_config{reason=\"updated\"} 1\n",
		},
		{
			"expvar_label_map",
			"counter_labelmap_keyname_m",
			func() *expvar.Map {
				m := new(expvar.Map)
				m.Init()
				m.Add("foo", 1)
				m.Add("bar", 2)
				return m
			}(),
			"# TYPE m counter\nm{keyname=\"bar\"} 2\nm{keyname=\"foo\"} 1\n",
		},
		{
			"struct_reflect",
			"foo",
			someExpVarWithJSONAndPromTypes(),
			strings.TrimSpace(`
# TYPE foo_nestvalue_foo gauge
foo_nestvalue_foo 1
# TYPE foo_nestvalue_bar counter
foo_nestvalue_bar 2
# TYPE foo_nestptr_foo gauge
foo_nestptr_foo 10
# TYPE foo_nestptr_bar counter
foo_nestptr_bar 20
# TYPE foo_curX gauge
foo_curX 3
# TYPE foo_totalY counter
foo_totalY 4
# TYPE foo_curTemp gauge
foo_curTemp 20.6
# TYPE foo_AnInt8 counter
foo_AnInt8 127
# TYPE foo_AUint16 counter
foo_AUint16 65535
`) + "\n",
		},
		{
			"struct_reflect_nil_root",
			"foo",
			expvarAdapter{(*SomeStats)(nil)},
			"",
		},
		{
			"func_returning_int",
			"num_goroutines",
			expvar.Func(func() any { return 123 }),
			"num_goroutines 123\n",
		},
		{
			"var_that_exports_itself",
			"custom_var",
			promWriter{},
			"custom_var_value 42\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() { expvarDo = expvar.Do }()
			expvarDo = func(f func(expvar.KeyValue)) {
				f(expvar.KeyValue{Key: tt.k, Value: tt.v})
			}
			rec := httptest.NewRecorder()
			VarzHandler(rec, httptest.NewRequest("GET", "/", nil))
			if got := rec.Body.Bytes(); string(got) != tt.want {
				t.Errorf("mismatch\n got: %q\n%s\nwant: %q\n%s\n", got, got, tt.want, tt.want)
			}
		})
	}
}

type SomeNested struct {
	FooG int64 `json:"foo" metrictype:"gauge"`
	BarC int64 `json:"bar" metrictype:"counter"`
	Omit int   `json:"-" metrictype:"counter"`
}

type SomeStats struct {
	Nested       SomeNested  `json:"nestvalue"`
	NestedPtr    *SomeNested `json:"nestptr"`
	NestedNilPtr *SomeNested `json:"nestnilptr"`
	CurX         int         `json:"curX" metrictype:"gauge"`
	NoMetricType int         `json:"noMetric" metrictype:""`
	TotalY       int64       `json:"totalY,omitempty" metrictype:"counter"`
	CurTemp      float64     `json:"curTemp" metrictype:"gauge"`
	AnInt8       int8        `metrictype:"counter"`
	AUint16      uint16      `metrictype:"counter"`
}

// someExpVarWithJSONAndPromTypes returns an expvar.Var that
// implements PrometheusMetricsReflectRooter for TestVarzHandler.
func someExpVarWithJSONAndPromTypes() expvar.Var {
	st := &SomeStats{
		Nested: SomeNested{
			FooG: 1,
			BarC: 2,
			Omit: 3,
		},
		NestedPtr: &SomeNested{
			FooG: 10,
			BarC: 20,
		},
		CurX:    3,
		TotalY:  4,
		CurTemp: 20.6,
		AnInt8:  127,
		AUint16: 65535,
	}
	return expvarAdapter{st}
}

type expvarAdapter struct {
	st *SomeStats
}

func (expvarAdapter) String() string { return "{}" } // expvar JSON; unused in test

func (a expvarAdapter) PrometheusMetricsReflectRoot() any {
	return a.st
}

type promWriter struct{}

func (promWriter) WritePrometheus(w io.Writer, prefix string) {
	fmt.Fprintf(w, "%s_value 42\n", prefix)
}

func (promWriter) String() string {
	return ""
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
