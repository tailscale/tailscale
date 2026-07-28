// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package example

import "sync"

// Bad: var declarations.
var l int // want `do not use "l"`
var I int // want `do not use "I"`

// OK: variables named "ll", "II", "i" are fine.
var (
	ll int
	II int
	i  int
)

// Bad: const declaration in a function scope.
func F0() {
	const l = 3 // want `do not use "l"`
	const I = 4 // want `do not use "I"`
	_ = l
	_ = I
}

// Bad: function parameters.
func F1a(l int) {} // want `do not use "l"`
func F1b(I int) {} // want `do not use "I"`

// Bad: named return values.
func F2a() (l int) { return } // want `do not use "l"`
func F2b() (I int) { return } // want `do not use "I"`

// Bad: receiver names.
type T struct{}

func (l *T) Ml() {} // want `do not use "l"`
func (I *T) MI() {} // want `do not use "I"`

// Bad: struct fields.
type S struct {
	l int // want `do not use "l"`
	I int // want `do not use "I"`
}

// Bad: short variable declarations.
func F3() {
	l := 1 // want `do not use "l"`
	I := 2 // want `do not use "I"`
	_ = l
	_ = I
}

// Bad: var statement inside a function.
func F4() {
	var l int // want `do not use "l"`
	var I int // want `do not use "I"`
	_ = l
	_ = I
}

// Bad: range key/value.
func F5(xs []int) {
	for l, v := range xs { // want `do not use "l"`
		_ = l
		_ = v
	}
	for _, I := range xs { // want `do not use "I"`
		_ = I
	}
}

// Bad: type parameters.
func F6a[l any](x l) l { return x } // want `do not use "l"`
func F6b[I any](x I) I { return x } // want `do not use "I"`

// Bad: type switch guards.
func F7(x any) {
	switch l := x.(type) { // want `do not use "l"`
	case int:
		_ = l
	}
	switch I := x.(type) { // want `do not use "I"`
	case int:
		_ = I
	}
}

// OK: clean code with no banned variables.
func F8() {
	count := 0
	for i := 0; i < 10; i++ {
		count++
	}
	_ = count
}

// OK: sync.Mutex named "mu".
var mu sync.Mutex
