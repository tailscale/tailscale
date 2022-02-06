// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type intValue int

func (i *intValue) Set(value string, opt Option) error {
	v, err := strconv.ParseInt(value, 0, strconv.IntSize)
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
	*i = intValue(v)
	return nil
}

func (i *intValue) String() string {
	return strconv.FormatInt(int64(*i), 10)
}

// Int creates an option that parses its value as an integer.
func Int(name rune, value int, helpvalue ...string) *int {
	return CommandLine.Int(name, value, helpvalue...)
}

func (s *Set) Int(name rune, value int, helpvalue ...string) *int {
	return s.IntLong("", name, value, helpvalue...)
}

func IntLong(name string, short rune, value int, helpvalue ...string) *int {
	return CommandLine.IntLong(name, short, value, helpvalue...)
}

func (s *Set) IntLong(name string, short rune, value int, helpvalue ...string) *int {
	s.IntVarLong(&value, name, short, helpvalue...)
	return &value
}

func IntVar(p *int, name rune, helpvalue ...string) Option {
	return CommandLine.IntVar(p, name, helpvalue...)
}

func (s *Set) IntVar(p *int, name rune, helpvalue ...string) Option {
	return s.IntVarLong(p, "", name, helpvalue...)
}

func IntVarLong(p *int, name string, short rune, helpvalue ...string) Option {
	return CommandLine.IntVarLong(p, name, short, helpvalue...)
}

func (s *Set) IntVarLong(p *int, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*intValue)(p), name, short, helpvalue...)
}
