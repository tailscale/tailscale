// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import "errors"

type enumValue string

var enumValues = make(map[*enumValue]map[string]struct{})

func (s *enumValue) Set(value string, opt Option) error {
	es, ok := enumValues[s]
	if !ok || es == nil {
		return errors.New("this option has no values")
	}
	if _, ok := es[value]; !ok {
		return errors.New("invalid value: " + value)
	}
	*s = enumValue(value)
	return nil
}

func (s *enumValue) String() string {
	return string(*s)
}

// Enum creates an option that can only be set to one of the enumerated strings
// passed in values.  Passing nil or an empty slice results in an option that
// will always fail.
func Enum(name rune, values []string, helpvalue ...string) *string {
	return CommandLine.Enum(name, values, helpvalue...)
}

func (s *Set) Enum(name rune, values []string, helpvalue ...string) *string {
	var p string
	s.EnumVarLong(&p, "", name, values, helpvalue...)
	return &p
}

func EnumLong(name string, short rune, values []string, helpvalue ...string) *string {
	return CommandLine.EnumLong(name, short, values, helpvalue...)
}

func (s *Set) EnumLong(name string, short rune, values []string, helpvalue ...string) *string {
	var p string
	s.EnumVarLong(&p, name, short, values, helpvalue...)
	return &p
}

// EnumVar creates an enum option that defaults to the starting value of *p.
// If *p is not found in values then a reset of this option will fail.
func EnumVar(p *string, name rune, values []string, helpvalue ...string) Option {
	return CommandLine.EnumVar(p, name, values, helpvalue...)
}

func (s *Set) EnumVar(p *string, name rune, values []string, helpvalue ...string) Option {
	return s.EnumVarLong(p, "", name, values, helpvalue...)
}

func EnumVarLong(p *string, name string, short rune, values []string, helpvalue ...string) Option {
	return CommandLine.EnumVarLong(p, name, short, values, helpvalue...)
}

func (s *Set) EnumVarLong(p *string, name string, short rune, values []string, helpvalue ...string) Option {
	m := make(map[string]struct{})
	for _, v := range values {
		m[v] = struct{}{}
	}
	enumValues[(*enumValue)(p)] = m
	return s.VarLong((*enumValue)(p), name, short, helpvalue...)
}
