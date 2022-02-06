// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type uint16Value uint16

func (i *uint16Value) Set(value string, opt Option) error {
	v, err := strconv.ParseUint(value, 0, 16)
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
	*i = uint16Value(v)
	return nil
}

func (i *uint16Value) String() string {
	return strconv.FormatUint(uint64(*i), 10)
}

// Uint16 creates an option that parses its value as an uint16.
func Uint16(name rune, value uint16, helpvalue ...string) *uint16 {
	return CommandLine.Uint16(name, value, helpvalue...)
}

func (s *Set) Uint16(name rune, value uint16, helpvalue ...string) *uint16 {
	return s.Uint16Long("", name, value, helpvalue...)
}

func Uint16Long(name string, short rune, value uint16, helpvalue ...string) *uint16 {
	return CommandLine.Uint16Long(name, short, value, helpvalue...)
}

func (s *Set) Uint16Long(name string, short rune, value uint16, helpvalue ...string) *uint16 {
	s.Uint16VarLong(&value, name, short, helpvalue...)
	return &value
}

func Uint16Var(p *uint16, name rune, helpvalue ...string) Option {
	return CommandLine.Uint16Var(p, name, helpvalue...)
}

func (s *Set) Uint16Var(p *uint16, name rune, helpvalue ...string) Option {
	return s.Uint16VarLong(p, "", name, helpvalue...)
}

func Uint16VarLong(p *uint16, name string, short rune, helpvalue ...string) Option {
	return CommandLine.Uint16VarLong(p, name, short, helpvalue...)
}

func (s *Set) Uint16VarLong(p *uint16, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*uint16Value)(p), name, short, helpvalue...)
}
