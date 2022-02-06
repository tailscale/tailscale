// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type int32Value int32

func (i *int32Value) Set(value string, opt Option) error {
	v, err := strconv.ParseInt(value, 0, 32)
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
	*i = int32Value(v)
	return nil
}

func (i *int32Value) String() string {
	return strconv.FormatInt(int64(*i), 10)
}

// Int32 creates an option that parses its value as an int32.
func Int32(name rune, value int32, helpvalue ...string) *int32 {
	return CommandLine.Int32(name, value, helpvalue...)
}

func (s *Set) Int32(name rune, value int32, helpvalue ...string) *int32 {
	return s.Int32Long("", name, value, helpvalue...)
}

func Int32Long(name string, short rune, value int32, helpvalue ...string) *int32 {
	return CommandLine.Int32Long(name, short, value, helpvalue...)
}

func (s *Set) Int32Long(name string, short rune, value int32, helpvalue ...string) *int32 {
	s.Int32VarLong(&value, name, short, helpvalue...)
	return &value
}

func Int32Var(p *int32, name rune, helpvalue ...string) Option {
	return CommandLine.Int32Var(p, name, helpvalue...)
}

func (s *Set) Int32Var(p *int32, name rune, helpvalue ...string) Option {
	return s.Int32VarLong(p, "", name, helpvalue...)
}

func Int32VarLong(p *int32, name string, short rune, helpvalue ...string) Option {
	return CommandLine.Int32VarLong(p, name, short, helpvalue...)
}

func (s *Set) Int32VarLong(p *int32, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*int32Value)(p), name, short, helpvalue...)
}
