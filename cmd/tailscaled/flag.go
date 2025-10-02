// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import "strconv"

// boolFlag is a flag.Value that tracks whether it was ever set.
type boolFlag struct {
	set bool
	v   bool
}

func (b *boolFlag) String() string {
	if b == nil || !b.set {
		return "unset"
	}
	return strconv.FormatBool(b.v)
}

func (b *boolFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	b.v = v
	b.set = true
	return nil
}

func (b *boolFlag) IsBoolFlag() bool { return true }
