// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type uintValue uint

func (i *uintValue) Set(value string, opt Option) error {
	v, err := strconv.ParseUint(value, 0, strconv.IntSize)
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
	*i = uintValue(v)
	return nil
}

func (i *uintValue) String() string {
	return strconv.FormatUint(uint64(*i), 10)
}

// Uint creates an option that parses its value as an unsigned integer.
func Uint(name rune, value uint, helpvalue ...string) *uint {
	return CommandLine.Uint(name, value, helpvalue...)
}

func (s *Set) Uint(name rune, value uint, helpvalue ...string) *uint {
	return s.UintLong("", name, value, helpvalue...)
}

func UintLong(name string, short rune, value uint, helpvalue ...string) *uint {
	return CommandLine.UintLong(name, short, value, helpvalue...)
}

func (s *Set) UintLong(name string, short rune, value uint, helpvalue ...string) *uint {
	s.UintVarLong(&value, name, short, helpvalue...)
	return &value
}

func UintVar(p *uint, name rune, helpvalue ...string) Option {
	return CommandLine.UintVar(p, name, helpvalue...)
}

func (s *Set) UintVar(p *uint, name rune, helpvalue ...string) Option {
	return s.UintVarLong(p, "", name, helpvalue...)
}

func UintVarLong(p *uint, name string, short rune, helpvalue ...string) Option {
	return CommandLine.UintVarLong(p, name, short, helpvalue...)
}

func (s *Set) UintVarLong(p *uint, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*uintValue)(p), name, short, helpvalue...)
}
