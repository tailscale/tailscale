// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import "strings"

type listValue []string

func (s *listValue) Set(value string, opt Option) error {
	a := strings.Split(value, ",")
	// If this is the first time we are seen then nil out the
	// default value.
	if opt.Count() <= 1 {
		*s = nil
	}
	*s = append(*s, a...)
	return nil
}

func (s *listValue) String() string {
	return strings.Join([]string(*s), ",")
}

// List creates an option that returns a slice of strings.  The parameters
// passed are converted from a comma seperated value list into a slice.
// Subsequent occurrences append to the list.
func List(name rune, helpvalue ...string) *[]string {
	return CommandLine.List(name, helpvalue...)
}

func (s *Set) List(name rune, helpvalue ...string) *[]string {
	p := []string{}
	s.ListVar(&p, name, helpvalue...)
	return &p
}

func ListLong(name string, short rune, helpvalue ...string) *[]string {
	return CommandLine.ListLong(name, short, helpvalue...)
}

func (s *Set) ListLong(name string, short rune, helpvalue ...string) *[]string {
	p := []string{}
	s.ListVarLong(&p, name, short, helpvalue...)
	return &p
}

// ListVar creats a list option and places the values in p.  If p is pointing
// to a list of values then those are considered the default values.  The first
// time name is seen in the options the list will be set to list specified by
// the parameter to the option.  Subsequent instances of the option will append
// to the list.
func ListVar(p *[]string, name rune, helpvalue ...string) Option {
	return CommandLine.ListVar(p, name, helpvalue...)
}

func (s *Set) ListVar(p *[]string, name rune, helpvalue ...string) Option {
	return s.ListVarLong(p, "", name, helpvalue...)
}

func ListVarLong(p *[]string, name string, short rune, helpvalue ...string) Option {
	return CommandLine.ListVarLong(p, name, short, helpvalue...)
}

func (s *Set) ListVarLong(p *[]string, name string, short rune, helpvalue ...string) Option {
	opt := s.VarLong((*listValue)(p), name, short, helpvalue...)
	return opt
}
