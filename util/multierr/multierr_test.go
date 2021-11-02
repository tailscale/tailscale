// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package multierr_test

import (
	"errors"
	"testing"

	qt "github.com/frankban/quicktest"
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
