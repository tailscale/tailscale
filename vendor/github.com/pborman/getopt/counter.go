// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type counterValue int

func (b *counterValue) Set(value string, opt Option) error {
	if value == "" {
		*b++
	} else {
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
		*b = counterValue(v)
	}
	return nil
}

func (b *counterValue) String() string {
	return strconv.Itoa(int(*b))
}

// Counter creates a counting flag stored as an int.  Each time the option
// is seen while parsing the value is incremented.  The value of the counter
// may be explicitly set by using the long form:
//
//  --counter=5
//  --c=5
//
// Further instances of the option will increment from the set value.
func Counter(name rune, helpvalue ...string) *int {
	return CommandLine.Counter(name, helpvalue...)
}

func (s *Set) Counter(name rune, helpvalue ...string) *int {
	var p int
	s.CounterVarLong(&p, "", name, helpvalue...)
	return &p
}

func CounterLong(name string, short rune, helpvalue ...string) *int {
	return CommandLine.CounterLong(name, short, helpvalue...)
}

func (s *Set) CounterLong(name string, short rune, helpvalue ...string) *int {
	var p int
	s.CounterVarLong(&p, name, short, helpvalue...)
	return &p
}

func CounterVar(p *int, name rune, helpvalue ...string) Option {
	return CommandLine.CounterVar(p, name, helpvalue...)
}

func (s *Set) CounterVar(p *int, name rune, helpvalue ...string) Option {
	return s.CounterVarLong(p, "", name, helpvalue...)
}

func CounterVarLong(p *int, name string, short rune, helpvalue ...string) Option {
	return CommandLine.CounterVarLong(p, name, short, helpvalue...)
}

func (s *Set) CounterVarLong(p *int, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*counterValue)(p), name, short, helpvalue...).SetFlag()
}
