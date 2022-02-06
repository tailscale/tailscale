// Copyright 2015 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import "time"

type durationValue time.Duration

func (d *durationValue) Set(value string, opt Option) error {
	v, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	*d = durationValue(v)
	return nil
}

func (d *durationValue) String() string {
	return time.Duration(*d).String()
}

// Duration creates an option that parses its value as a time.Duration.
func Duration(name rune, value time.Duration, helpvalue ...string) *time.Duration {
	return CommandLine.Duration(name, value, helpvalue...)
}

func (s *Set) Duration(name rune, value time.Duration, helpvalue ...string) *time.Duration {
	return s.DurationLong("", name, value, helpvalue...)
}

func DurationLong(name string, short rune, value time.Duration, helpvalue ...string) *time.Duration {
	return CommandLine.DurationLong(name, short, value, helpvalue...)
}

func (s *Set) DurationLong(name string, short rune, value time.Duration, helpvalue ...string) *time.Duration {
	s.DurationVarLong(&value, name, short, helpvalue...)
	return &value
}

func DurationVar(p *time.Duration, name rune, helpvalue ...string) Option {
	return CommandLine.DurationVar(p, name, helpvalue...)
}

func (s *Set) DurationVar(p *time.Duration, name rune, helpvalue ...string) Option {
	return s.DurationVarLong(p, "", name, helpvalue...)
}

func DurationVarLong(p *time.Duration, name string, short rune, helpvalue ...string) Option {
	return CommandLine.DurationVarLong(p, name, short, helpvalue...)
}

func (s *Set) DurationVarLong(p *time.Duration, name string, short rune, helpvalue ...string) Option {
	return s.VarLong((*durationValue)(p), name, short, helpvalue...)
}
