// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type int64Value int64

func (i *int64Value) Set(value string, opt Option) error {
	v, err := strconv.ParseInt(value, 0, 64)
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
	*i = int64Value(v)
	return nil
}

func (i *int64Value) String() string {
	return strconv.FormatInt(int64(*i), 10)
}

// Int64 creates an option that parses its value as an int64.
func Int64(name rune, value int64, helpvalue ...string) *int64 {
	return CommandLine.Int64(name, value, helpvalue...)
}

func (s *Set) Int64(name rune, value int64, helpvalue ...string) *int64 {
	return s.Int64Long("", name, value, helpvalue...)
}

func Int64Long(name string, short rune, value int64, helpvalue ...string) *int64 {
	return CommandLine.Int64Long(name, short, value, helpvalue...)
}

func (s *Set) Int64Long(name string, short rune, value int64, helpvalue ...string) *int64 {
	s.Int64VarLong(&value, name, short, helpvalue...)
	return &value
}

func Int64Var(p *int64, name rune, helpvalue ...string) Option {
	return CommandLine.Int64Var(p, name, helpvalue...)
}

func (s *Set) Int64Var(p *int64, name rune, helpvalue ...string) Option {
	return s.Int64VarLong(p, "", name, helpvalue...)
}

func Int64VarLong(p *int64, name string, short rune, helpvalue ...string) Option {
	return CommandLine.Int64VarLong(p, name, short, helpvalue...)
}

func (s *Set) Int64VarLong(p *int64, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*int64Value)(p), name, short, helpvalue...)
}
