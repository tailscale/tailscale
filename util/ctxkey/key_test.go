// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxkey

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

func TestKey(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	// Test keys with the same name as being distinct.
	k1 := New("same.Name", "")
	c.Assert(k1.String(), qt.Equals, "same.Name")
	k2 := New("same.Name", "")
	c.Assert(k2.String(), qt.Equals, "same.Name")
	c.Assert(k1 == k2, qt.Equals, false)
	ctx = k1.WithValue(ctx, "hello")
	c.Assert(k1.Has(ctx), qt.Equals, true)
	c.Assert(k1.Value(ctx), qt.Equals, "hello")
	c.Assert(k2.Has(ctx), qt.Equals, false)
	c.Assert(k2.Value(ctx), qt.Equals, "")
	ctx = k2.WithValue(ctx, "goodbye")
	c.Assert(k1.Has(ctx), qt.Equals, true)
	c.Assert(k1.Value(ctx), qt.Equals, "hello")
	c.Assert(k2.Has(ctx), qt.Equals, true)
	c.Assert(k2.Value(ctx), qt.Equals, "goodbye")

	// Test default value.
	k3 := New("mapreduce.Timeout", time.Hour)
	c.Assert(k3.Has(ctx), qt.Equals, false)
	c.Assert(k3.Value(ctx), qt.Equals, time.Hour)
	ctx = k3.WithValue(ctx, time.Minute)
	c.Assert(k3.Has(ctx), qt.Equals, true)
	c.Assert(k3.Value(ctx), qt.Equals, time.Minute)

	// Test incomparable value.
	k4 := New("slice", []int(nil))
	c.Assert(k4.Has(ctx), qt.Equals, false)
	c.Assert(k4.Value(ctx), qt.DeepEquals, []int(nil))
	ctx = k4.WithValue(ctx, []int{1, 2, 3})
	c.Assert(k4.Has(ctx), qt.Equals, true)
	c.Assert(k4.Value(ctx), qt.DeepEquals, []int{1, 2, 3})

	// Accessors should be allocation free.
	c.Assert(testing.AllocsPerRun(100, func() {
		k1.Value(ctx)
		k1.Has(ctx)
		k1.ValueOk(ctx)
	}), qt.Equals, 0.0)

	// Test keys that are created without New.
	var k5 Key[string]
	c.Assert(k5.String(), qt.Equals, "string")
	c.Assert(k1 == k5, qt.Equals, false) // should be different from key created by New
	c.Assert(k5.Has(ctx), qt.Equals, false)
	ctx = k5.WithValue(ctx, "fizz")
	c.Assert(k5.Value(ctx), qt.Equals, "fizz")
	var k6 Key[string]
	c.Assert(k6.String(), qt.Equals, "string")
	c.Assert(k5 == k6, qt.Equals, true)
	c.Assert(k6.Has(ctx), qt.Equals, true)
	ctx = k6.WithValue(ctx, "fizz")

	// Test interface value types.
	var k7 Key[any]
	c.Assert(k7.Has(ctx), qt.Equals, false)
	ctx = k7.WithValue(ctx, "whatever")
	c.Assert(k7.Value(ctx), qt.DeepEquals, "whatever")
	ctx = k7.WithValue(ctx, []int{1, 2, 3})
	c.Assert(k7.Value(ctx), qt.DeepEquals, []int{1, 2, 3})
	ctx = k7.WithValue(ctx, nil)
	c.Assert(k7.Has(ctx), qt.Equals, true)
	c.Assert(k7.Value(ctx), qt.DeepEquals, nil)
	k8 := New[error]("error", io.EOF)
	c.Assert(k8.Has(ctx), qt.Equals, false)
	c.Assert(k8.Value(ctx), qt.Equals, io.EOF)
	ctx = k8.WithValue(ctx, nil)
	c.Assert(k8.Value(ctx), qt.Equals, nil)
	c.Assert(k8.Has(ctx), qt.Equals, true)
	err := fmt.Errorf("read error: %w", io.ErrUnexpectedEOF)
	ctx = k8.WithValue(ctx, err)
	c.Assert(k8.Value(ctx), qt.Equals, err)
	c.Assert(k8.Has(ctx), qt.Equals, true)
}

func TestStringer(t *testing.T) {
	t.SkipNow() // TODO(https://go.dev/cl/555697): Enable this after fix is merged upstream.
	c := qt.New(t)
	ctx := context.Background()
	c.Assert(fmt.Sprint(New("foo.Bar", "").WithValue(ctx, "baz")), qt.Matches, regexp.MustCompile("foo.Bar.*baz"))
	c.Assert(fmt.Sprint(New("", []int{}).WithValue(ctx, []int{1, 2, 3})), qt.Matches, regexp.MustCompile(fmt.Sprintf("%[1]T.*%[1]v", []int{1, 2, 3})))
	c.Assert(fmt.Sprint(New("", 0).WithValue(ctx, 5)), qt.Matches, regexp.MustCompile("int.*5"))
	c.Assert(fmt.Sprint(Key[time.Duration]{}.WithValue(ctx, time.Hour)), qt.Matches, regexp.MustCompile(fmt.Sprintf("%[1]T.*%[1]v", time.Hour)))
}
