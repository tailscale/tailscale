// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package structs contains the Incomparable type.
package structs

// Incomparable is a zero-width incomparable type. If added as the
// first field in a struct, it marks that struct as not comparable
// (can't do == or be a map key) and usually doesn't add any width to
// the struct (unless the struct has only small fields).
//
// Be making a struct incomparable, you can prevent misuse (prevent
// people from using ==), but also you can shrink generated binaries,
// as the compiler can omit equality funcs from the binary.
type Incomparable [0]func()
