// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package httpbody

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"tailscale.com/util/must"
)

func mustReqWithContext(ctx context.Context) *http.Request {
	return must.Get(http.NewRequestWithContext(ctx, "GET", "https://example.com", nil))
}

func makeRes(body string) *http.Response {
	return &http.Response{
		Body: io.NopCloser(strings.NewReader(body)),
	}
}

type closeFunc func() error

func (f closeFunc) Read(p []byte) (int, error) { return 0, io.EOF }
func (f closeFunc) Close() error               { return f() }

func TestLimitSizeTo(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		max     int64
		want    string
		wantErr string // empty means success
	}{
		{
			name: "under-limit",
			body: "hello",
			max:  16,
			want: "hello",
		},
		{
			name: "exactly-at-limit",
			body: "hello",
			max:  5,
			want: "hello",
		},
		{
			name:    "over-limit",
			body:    "hello world",
			max:     5,
			want:    "hello",
			wantErr: ErrTooLarge.Error(),
		},
		{
			name: "empty-body",
			body: "",
			max:  1,
			want: "",
		},
		{
			name: "zero-max-is-no-op",
			body: "hello",
			max:  0,
			want: "hello",
		},
		{
			name: "negative-max-is-no-op",
			body: "hello",
			max:  -1,
			want: "hello",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := makeRes(tt.body)
			LimitSizeTo(res, tt.max)
			got, err := io.ReadAll(res.Body)
			if string(got) != tt.want {
				t.Errorf("got body %q, want %q", got, tt.want)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got error %v, want it to contain %q", err, tt.wantErr)
			}
			if !errors.Is(err, ErrTooLarge) {
				t.Errorf("error %v does not wrap ErrTooLarge", err)
			}
		})
	}
}

func TestLimitSizeStickyError(t *testing.T) {
	res := makeRes("hello world")
	LimitSizeTo(res, 5)
	buf := make([]byte, 3)
	if n, err := res.Body.Read(buf); n != 3 || err != nil {
		t.Fatalf("first Read = %d, %v; want 3, nil", n, err)
	}
	// The second read consumes the last allowed bytes.
	if n, err := res.Body.Read(buf); n != 2 || err != nil {
		t.Fatalf("second Read = %d, %v; want 2, nil", n, err)
	}
	// Every subsequent read reports the too-large error.
	for range 3 {
		if n, err := res.Body.Read(buf); n != 0 || !errors.Is(err, ErrTooLarge) {
			t.Fatalf("subsequent Read = %d, %v; want 0, ErrTooLarge", n, err)
		}
	}
}

func TestLimitSizeLargeRead(t *testing.T) {
	// A single Read call with a buffer bigger than the limit must not
	// over-read the underlying body.
	res := makeRes(strings.Repeat("a", 100))
	LimitSizeTo(res, 10)
	got, err := io.ReadAll(res.Body)
	if string(got) != strings.Repeat("a", 10) {
		t.Errorf("got %d bytes, want 10", len(got))
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

func TestLimitSizeClose(t *testing.T) {
	var closed bool
	res := &http.Response{
		Body: closeFunc(func() error {
			closed = true
			return nil
		}),
	}
	LimitSizeTo(res, 1<<20)
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Error("Close was not passed through to the underlying body")
	}
}

func TestLimitSizeJSONDecodeOverLimit(t *testing.T) {
	// A streaming decoder must see the too-large error rather than a
	// silently truncated document.
	res := makeRes(`{"a": "` + strings.Repeat("x", 100) + `"}`)
	LimitSizeTo(res, 10)
	var v map[string]any
	err := json.NewDecoder(res.Body).Decode(&v)
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("json decode err = %v, want ErrTooLarge", err)
	}
}

func TestLimitSize(t *testing.T) {
	// LimitSize looks the cap up from res.Request's context, falling back
	// to DefaultMaxSize when the context carries no override and when res
	// has no Request at all.
	overDefault := strings.Repeat("a", int(DefaultMaxSize)+1)

	newRes := func(setMax func(context.Context) context.Context) *http.Response {
		ctx := context.Background()
		if setMax != nil {
			ctx = setMax(ctx)
		}
		req := mustReqWithContext(ctx)
		return &http.Response{Request: req, Body: io.NopCloser(strings.NewReader(overDefault))}
	}

	tests := []struct {
		name   string
		res    *http.Response
		wantOK bool
	}{
		{name: "no-override-uses-default", res: newRes(nil)},
		{name: "override-larger", res: newRes(func(ctx context.Context) context.Context {
			return WithMaxSize(ctx, DefaultMaxSize*2)
		}), wantOK: true},
		{name: "override-smaller", res: newRes(func(ctx context.Context) context.Context {
			return WithMaxSize(ctx, 10)
		})},
		{name: "override-unlimited", res: newRes(func(ctx context.Context) context.Context {
			return WithMaxSize(ctx, 0)
		}), wantOK: true},
		// A hand-built Response with no Request falls back to the default.
		{name: "no-request-uses-default", res: &http.Response{Body: io.NopCloser(strings.NewReader(overDefault))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			LimitSize(tt.res)
			got, err := io.ReadAll(tt.res.Body)
			if tt.wantOK {
				if err != nil {
					t.Fatalf("reading body of %d bytes: %v", len(overDefault), err)
				}
				if string(got) != overDefault {
					t.Errorf("got %d bytes, want %d", len(got), len(overDefault))
				}
				return
			}
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("err = %v, want ErrTooLarge", err)
			}
		})
	}
}

func TestLimitSizeToReplacesPreviousLimit(t *testing.T) {
	// A second LimitSizeTo replaces the first rather than compounding
	// it: with nesting, the smaller limit would always win, so the limit
	// could never be raised.
	res := makeRes(strings.Repeat("a", 50))
	LimitSizeTo(res, 10)
	LimitSizeTo(res, 100)
	got, err := io.ReadAll(res.Body)
	if err != nil || len(got) != 50 {
		t.Fatalf("after raising the limit: got %d bytes, %v; want 50, nil", len(got), err)
	}

	res = makeRes(strings.Repeat("a", 50))
	LimitSizeTo(res, 100)
	LimitSizeTo(res, 10)
	got, err = io.ReadAll(res.Body)
	if string(got) != strings.Repeat("a", 10) {
		t.Errorf("after lowering the limit: got %d bytes, want 10", len(got))
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("after lowering the limit: err = %v, want ErrTooLarge", err)
	}
}

func TestLimitSizeZeroRemovesPreviousLimit(t *testing.T) {
	res := makeRes("hello world")
	LimitSizeTo(res, 5)
	LimitSizeTo(res, 0)
	got, err := io.ReadAll(res.Body)
	if err != nil || string(got) != "hello world" {
		t.Fatalf("LimitSizeTo(0): got %q, %v; want the full body, nil", got, err)
	}

	// LimitSize with an unlimited context also removes a previous limit.
	res = makeRes("hello world")
	LimitSizeTo(res, 5)
	res.Request = mustReqWithContext(WithMaxSize(context.Background(), 0))
	LimitSize(res)
	got, err = io.ReadAll(res.Body)
	if err != nil || string(got) != "hello world" {
		t.Fatalf("LimitSize with unlimited context: got %q, %v; want the full body, nil", got, err)
	}
}

func TestMaxSizeContext(t *testing.T) {
	if got := MaxSize(context.Background()); got != DefaultMaxSize {
		t.Errorf("MaxSize(background) = %d, want %d", got, DefaultMaxSize)
	}
	ctx := WithMaxSize(context.Background(), 10<<20)
	if got := MaxSize(ctx); got != 10<<20 {
		t.Errorf("MaxSize(override) = %d, want %d", got, 10<<20)
	}
	// Zero means unlimited.
	ctx = WithMaxSize(context.Background(), 0)
	if got := MaxSize(ctx); got != 0 {
		t.Errorf("MaxSize(unlimited) = %d, want 0", got)
	}
}
