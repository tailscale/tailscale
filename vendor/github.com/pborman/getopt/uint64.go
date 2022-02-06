// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type uint64Value uint64

func (i *uint64Value) Set(value string, opt Option) error {
	v, err := strconv.ParseUint(value, 0, 64)
	if err != nil {
		if e, ok := err.(*strconv.NumError); ok {
			switch e.Err {
			case strconv.ErrRange:
				err = fmt.Errorf("value out of range: %s", value)
			case strconv.ErrSyntax:
				err = fmt.Errorf("not a valid number: %s", value)
			}
		}
		return err
	}
	*i = uint64Value(v)
	return nil
}

func (i *uint64Value) String() string {
	return strconv.FormatUint(uint64(*i), 10)
}

// Uint64 creates an option that parses its value as a uint64.
func Uint64(name rune, value uint64, helpvalue ...string) *uint64 {
	return CommandLine.Uint64(name, value, helpvalue...)
}

func (s *Set) Uint64(name rune, value uint64, helpvalue ...string) *uint64 {
	return s.Uint64Long("", name, value, helpvalue...)
}

func Uint64Long(name string, short rune, value uint64, helpvalue ...string) *uint64 {
	return CommandLine.Uint64Long(name, short, value, helpvalue...)
}

func (s *Set) Uint64Long(name string, short rune, value uint64, helpvalue ...string) *uint64 {
	s.Uint64VarLong(&value, name, short, helpvalue...)
	return &value
}

func Uint64Var(p *uint64, name rune, helpvalue ...string) Option {
	return CommandLine.Uint64Var(p, name, helpvalue...)
}

func (s *Set) Uint64Var(p *uint64, name rune, helpvalue ...string) Option {
	return s.Uint64VarLong(p, "", name, helpvalue...)
}

func Uint64VarLong(p *uint64, name string, short rune, helpvalue ...string) Option {
	return CommandLine.Uint64VarLong(p, name, short, helpvalue...)
}

func (s *Set) Uint64VarLong(p *uint64, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*uint64Value)(p), name, short, helpvalue...)
}
