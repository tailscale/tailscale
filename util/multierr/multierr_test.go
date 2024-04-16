// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multierr_test

import (
	"errors"
	"fmt"
	"io"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/util/multierr"
)

func TestAll(t *testing.T) {
	C := qt.New(t)
	eqErr := qt.CmpEquals(cmpopts.EquateErrors())

	type E = []error
	N := multierr.New

	a := errors.New("a")
	b := errors.New("b")
	c := errors.New("c")
	d := errors.New("d")
	x := errors.New("x")
	abcd := E{a, b, c, d}

	tests := []struct {
		In         E       // input to New
		WantNil    bool    // want nil returned?
		WantSingle error   // if non-nil, want this single error returned
		WantErrors []error // if non-nil, want an Error composed of these errors returned
	}{
		{In: nil, WantNil: true},

		{In: E{nil}, WantNil: true},
		{In: E{nil, nil}, WantNil: true},

		{In: E{a}, WantSingle: a},
		{In: E{a, nil}, WantSingle: a},
		{In: E{nil, a}, WantSingle: a},
		{In: E{nil, a, nil}, WantSingle: a},

		{In: E{a, b}, WantErrors: E{a, b}},
		{In: E{nil, a, nil, b, nil}, WantErrors: E{a, b}},

		{In: E{a, b, N(c, d)}, WantErrors: E{a, b, c, d}},
		{In: E{a, N(b, c), d}, WantErrors: E{a, b, c, d}},
		{In: E{N(a, b), c, d}, WantErrors: E{a, b, c, d}},
		{In: E{N(a, b), N(c, d)}, WantErrors: E{a, b, c, d}},
		{In: E{nil, N(a, nil, b), nil, N(c, d)}, WantErrors: E{a, b, c, d}},

		{In: E{N(a, N(b, N(c, N(d))))}, WantErrors: E{a, b, c, d}},
		{In: E{N(N(N(N(a), b), c), d)}, WantErrors: E{a, b, c, d}},

		{In: E{N(abcd...)}, WantErrors: E{a, b, c, d}},
		{In: E{N(abcd...), N(abcd...)}, WantErrors: E{a, b, c, d, a, b, c, d}},
	}

	for _, test := range tests {
		got := multierr.New(test.In...)
		if test.WantNil {
			C.Assert(got, qt.IsNil)
			continue
		}
		if test.WantSingle != nil {
			C.Assert(got, eqErr, test.WantSingle)
			continue
		}
		ee, _ := got.(multierr.Error)
		C.Assert(ee.Errors(), eqErr, test.WantErrors)

		for _, e := range test.WantErrors {
			C.Assert(ee.Is(e), qt.IsTrue)
		}
		C.Assert(ee.Is(x), qt.IsFalse)
	}
}

func TestRange(t *testing.T) {
	C := qt.New(t)

	errA := errors.New("A")
	errB := errors.New("B")
	errC := errors.New("C")
	errD := errors.New("D")
	errCD := multierr.New(errC, errD)
	errCD1 := fmt.Errorf("1:%w", errCD)
	errE := errors.New("E")
	errE1 := fmt.Errorf("1:%w", errE)
	errE2 := fmt.Errorf("2:%w", errE1)
	errF := errors.New("F")
	root := multierr.New(errA, errB, errCD1, errE2, errF)

	var got []error
	want := []error{root, errA, errB, errCD1, errCD, errC, errD, errE2, errE1, errE, errF}
	multierr.Range(root, func(err error) bool {
		got = append(got, err)
		return true
	})
	C.Assert(got, qt.CmpEquals(cmp.Comparer(func(x, y error) bool {
		return x.Error() == y.Error()
	})), want)
}

var sink error

func BenchmarkEmpty(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		sink = multierr.New(nil, nil, nil, multierr.Error{})
	}
}

func BenchmarkNonEmpty(b *testing.B) {
	merr := multierr.New(io.ErrShortBuffer, io.ErrNoProgress)
	b.ReportAllocs()
	for range b.N {
		sink = multierr.New(io.ErrUnexpectedEOF, merr, io.ErrClosedPipe)
	}
}
