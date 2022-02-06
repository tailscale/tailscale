// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type uint32Value uint32

func (i *uint32Value) Set(value string, opt Option) error {
	v, err := strconv.ParseUint(value, 0, 32)
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
	*i = uint32Value(v)
	return nil
}

func (i *uint32Value) String() string {
	return strconv.FormatUint(uint64(*i), 10)
}

// Uint32 creates an option that parses its value as an uint32.
func Uint32(name rune, value uint32, helpvalue ...string) *uint32 {
	return CommandLine.Uint32(name, value, helpvalue...)
}

func (s *Set) Uint32(name rune, value uint32, helpvalue ...string) *uint32 {
	return s.Uint32Long("", name, value, helpvalue...)
}

func Uint32Long(name string, short rune, value uint32, helpvalue ...string) *uint32 {
	return CommandLine.Uint32Long(name, short, value, helpvalue...)
}

func (s *Set) Uint32Long(name string, short rune, value uint32, helpvalue ...string) *uint32 {
	s.Uint32VarLong(&value, name, short, helpvalue...)
	return &value
}

func Uint32Var(p *uint32, name rune, helpvalue ...string) Option {
	return CommandLine.Uint32Var(p, name, helpvalue...)
}

func (s *Set) Uint32Var(p *uint32, name rune, helpvalue ...string) Option {
	return s.Uint32VarLong(p, "", name, helpvalue...)
}

func Uint32VarLong(p *uint32, name string, short rune, helpvalue ...string) Option {
	return CommandLine.Uint32VarLong(p, name, short, helpvalue...)
}

func (s *Set) Uint32VarLong(p *uint32, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*uint32Value)(p), name, short, helpvalue...)
}
