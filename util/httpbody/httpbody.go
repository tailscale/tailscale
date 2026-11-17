// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package httpbody provides helpers for reading HTTP response bodies
// defensively, capping how much memory a response can make the reader
// buffer.
//
// A typical HTTP client applies the cap in its Do method, so every
// response it returns is capped unless the request opts out:
//
//	res, err := c.Client.Do(req)
//	httpbody.LimitSize(res)
package httpbody

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"tailscale.com/util/ctxkey"
)

// ErrTooLarge is reported by a body wrapped with [LimitSize] once more
// than the configured number of bytes have been read. The error text
// includes the limit that was exceeded.
var ErrTooLarge = errors.New("response body too large")

// DefaultMaxSize is the default response body size cap, in bytes, used
// when a context carries no override set with [WithMaxSize]. HTTP clients
// that apply response body caps should honor it, so requests can tune or
// disable the cap uniformly across clients.
const DefaultMaxSize = 1 << 20

// maxSizeKey is the context key carrying the response body size cap.
var maxSizeKey = ctxkey.New[int64]("httpbody.maxSize", DefaultMaxSize)

// WithMaxSize returns a context that sets the response body size cap to
// max, instead of [DefaultMaxSize], for HTTP clients that apply response
// body caps. A max of zero or less disables the cap. Disable it for
// responses that stream an unbounded number of individually bounded
// messages, like a streaming map response.
func WithMaxSize(ctx context.Context, max int64) context.Context {
	return maxSizeKey.WithValue(ctx, max)
}

// MaxSize returns the response body size cap in ctx: the value set with
// [WithMaxSize], or [DefaultMaxSize] if ctx carries none.
func MaxSize(ctx context.Context) int64 {
	return maxSizeKey.Value(ctx)
}

// LimitSize replaces res.Body with a wrapper that fails reads with an
// error wrapping [ErrTooLarge] once more than the response body size
// limit in res.Request's context, per [WithMaxSize], has been read:
// [DefaultMaxSize] by default, or if res has no Request. A limit of zero
// or less imposes no limit, removing any limit a previous call set.
//
// Repeated calls to LimitSize or LimitSizeTo replace the previous limit
// rather than compounding it, so a later call can raise or remove the
// limit an earlier one set. If bytes have already been read through a
// previous limit, the new limit counts bytes read after it was applied.
//
// Unlike io.LimitReader, which silently truncates at its limit, the
// wrapper reports an oversize body so callers can distinguish a short
// body from a too-large one. A body of at most the limit, including one
// of exactly the limit, reads back without error.
func LimitSize(res *http.Response) {
	max := int64(DefaultMaxSize)
	if res.Request != nil {
		max = MaxSize(res.Request.Context())
	}
	limitSizeTo(res, max)
}

// LimitSizeTo is like [LimitSize] but caps res.Body at exactly max bytes,
// ignoring any override in res.Request's context. A max of zero or less
// imposes no limit, removing any limit a previous call set. Repeated
// calls to LimitSize or LimitSizeTo replace the previous limit rather
// than compounding it.
func LimitSizeTo(res *http.Response, max int64) {
	limitSizeTo(res, max)
}

func limitSizeTo(res *http.Response, max int64) {
	// Unwrap any limit a previous call set instead of wrapping it again:
	// nested limits would compound, with the smaller always winning, so
	// re-limiting could never raise the cap. At most one wrapper can
	// exist, because this always unwraps first.
	if lb, ok := res.Body.(*limitedBody); ok {
		res.Body = lb.body
	}
	if max <= 0 {
		return
	}
	res.Body = &limitedBody{body: res.Body, max: max, remain: max}
}

// limitedBody is the io.ReadCloser installed by [LimitSize].
type limitedBody struct {
	body io.ReadCloser
	max  int64 // the limit, for error reporting
	// remain is the number of bytes still allowed. Once the limit is
	// exhausted, a one-byte probe of body distinguishes a body of exactly
	// max bytes (EOF, fine) from one with more to come. remain goes
	// negative once oversize is detected, and stays there.
	remain int64
}

func (b *limitedBody) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.remain < 0 {
		return 0, b.tooLarge()
	}
	if b.remain == 0 {
		// The limit is exhausted. A body of exactly max bytes is legal, so
		// check whether the body has actually ended before declaring it
		// too large. The probed byte, if any, is dropped: once a body is
		// too large, callers only want the error.
		var probe [1]byte
		m, err := b.body.Read(probe[:])
		if m == 0 && err != nil {
			return 0, err // io.EOF, or the underlying error
		}
		b.remain = -1
		return 0, b.tooLarge()
	}
	if int64(len(p)) > b.remain {
		p = p[:b.remain]
	}
	n, err = b.body.Read(p)
	b.remain -= int64(n)
	return n, err
}

func (b *limitedBody) Close() error {
	return b.body.Close()
}

func (b *limitedBody) tooLarge() error {
	return fmt.Errorf("%w: limit %d bytes", ErrTooLarge, b.max)
}
