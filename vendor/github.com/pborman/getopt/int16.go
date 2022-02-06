// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type int16Value int16

func (i *int16Value) Set(value string, opt Option) error {
	v, err := strconv.ParseInt(value, 0, 16)
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
	*i = int16Value(v)
	return nil
}

func (i *int16Value) String() string {
	return strconv.FormatInt(int64(*i), 10)
}

// Int16 creates an option that parses its value as an int16.
func Int16(name rune, value int16, helpvalue ...string) *int16 {
	return CommandLine.Int16(name, value, helpvalue...)
}

func (s *Set) Int16(name rune, value int16, helpvalue ...string) *int16 {
	return s.Int16Long("", name, value, helpvalue...)
}

func Int16Long(name string, short rune, value int16, helpvalue ...string) *int16 {
	return CommandLine.Int16Long(name, short, value, helpvalue...)
}

func (s *Set) Int16Long(name string, short rune, value int16, helpvalue ...string) *int16 {
	s.Int16VarLong(&value, name, short, helpvalue...)
	return &value
}

func Int16Var(p *int16, name rune, helpvalue ...string) Option {
	return CommandLine.Int16Var(p, name, helpvalue...)
}

func (s *Set) Int16Var(p *int16, name rune, helpvalue ...string) Option {
	return s.Int16VarLong(p, "", name, helpvalue...)
}

func Int16VarLong(p *int16, name string, short rune, helpvalue ...string) Option {
	return CommandLine.Int16VarLong(p, name, short, helpvalue...)
}

func (s *Set) Int16VarLong(p *int16, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*int16Value)(p), name, short, helpvalue...)
}
