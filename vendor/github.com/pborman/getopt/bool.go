// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strings"
)

type boolValue bool

func (b *boolValue) Set(value string, opt Option) error {
	switch strings.ToLower(value) {
	case "", "1", "true", "on", "t":
		*b = true
	case "0", "false", "off", "f":
		*b = false
	default:
		return fmt.Errorf("invalid value for bool %s: %q", opt.Name(), value)
	}
	return nil
}

func (b *boolValue) String() string {
	if *b {
		return "true"
	}
	return "false"
}

// Bool creates a flag option that is a bool.  Bools normally do not take a
// value however one can be assigned by using the long form of the option:
//
//  --option=true
//  --o=false
//
// Its value is case insenstive and one of true, false, t, f, on, off, t and 0.
func Bool(name rune, helpvalue ...string) *bool {
	return CommandLine.Bool(name, helpvalue...)
}

func (s *Set) Bool(name rune, helpvalue ...string) *bool {
	var p bool
	s.BoolVarLong(&p, "", name, helpvalue...)
	return &p
}

func BoolLong(name string, short rune, helpvalue ...string) *bool {
	return CommandLine.BoolLong(name, short, helpvalue...)
}

func (s *Set) BoolLong(name string, short rune, helpvalue ...string) *bool {
	var p bool
	s.BoolVarLong(&p, name, short, helpvalue...)
	return &p
}

func BoolVar(p *bool, name rune, helpvalue ...string) Option {
	return CommandLine.BoolVar(p, name, helpvalue...)
}

func (s *Set) BoolVar(p *bool, name rune, helpvalue ...string) Option {
	return s.BoolVarLong(p, "", name, helpvalue...)
}

func BoolVarLong(p *bool, name string, short rune, helpvalue ...string) Option {
	return CommandLine.BoolVarLong(p, name, short, helpvalue...)
}

func (s *Set) BoolVarLong(p *bool, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*boolValue)(p), name, short, helpvalue...).SetFlag()
}
