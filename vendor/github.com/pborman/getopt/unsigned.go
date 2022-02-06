// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type unsigned uint64

type UnsignedLimit struct {
	Base int    // Base for conversion as per strconv.ParseInt
	Bits int    // Number of bits as per strconv.ParseInt
	Min  uint64 // Minimum allowed value if both Min and Max are not 0
	Max  uint64 // Maximum allowed value if both Min and Max are not 0
}

var unsignedLimits = make(map[*unsigned]*UnsignedLimit)

func (n *unsigned) Set(value string, opt Option) error {
	l := unsignedLimits[n]
	if l == nil {
		return fmt.Errorf("no limits defined for %s", opt.Name())
	}
	v, err := strconv.ParseUint(value, l.Base, l.Bits)
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
	if l.Min != 0 || l.Max != 0 {
		if v < l.Min {
			return fmt.Errorf("value out of range (<%v): %s", l.Min, value)
		}
		if v > l.Max {
			return fmt.Errorf("value out of range (>%v): %s", l.Max, value)
		}
	}
	*n = unsigned(v)
	return nil
}

func (n *unsigned) String() string {
	l := unsignedLimits[n]
	if l != nil && l.Base != 0 {
		return strconv.FormatUint(uint64(*n), l.Base)
	}
	return strconv.FormatUint(uint64(*n), 10)
}

// Unsigned creates an option that is stored in a uint64 and is
// constrained by the limits pointed to by l.  The Max and Min values are only
// used if at least one of the values are not 0.   If Base is 0, the base is
// implied by the string's prefix: base 16 for "0x", base 8 for "0", and base
// 10 otherwise.
func Unsigned(name rune, value uint64, l *UnsignedLimit, helpvalue ...string) *uint64 {
	return CommandLine.Unsigned(name, value, l, helpvalue...)
}

func (s *Set) Unsigned(name rune, value uint64, l *UnsignedLimit, helpvalue ...string) *uint64 {
	return s.UnsignedLong("", name, value, l, helpvalue...)
}

func UnsignedLong(name string, short rune, value uint64, l *UnsignedLimit, helpvalue ...string) *uint64 {
	return CommandLine.UnsignedLong(name, short, value, l, helpvalue...)
}

func (s *Set) UnsignedLong(name string, short rune, value uint64, l *UnsignedLimit, helpvalue ...string) *uint64 {
	s.UnsignedVarLong(&value, name, short, l, helpvalue...)
	return &value
}

func UnsignedVar(p *uint64, name rune, l *UnsignedLimit, helpvalue ...string) Option {
	return CommandLine.UnsignedVar(p, name, l, helpvalue...)
}

func (s *Set) UnsignedVar(p *uint64, name rune, l *UnsignedLimit, helpvalue ...string) Option {
	return s.UnsignedVarLong(p, "", name, l, helpvalue...)
}

func UnsignedVarLong(p *uint64, name string, short rune, l *UnsignedLimit, helpvalue ...string) Option {
	return CommandLine.UnsignedVarLong(p, name, short, l, helpvalue...)
}

func (s *Set) UnsignedVarLong(p *uint64, name string, short rune, l *UnsignedLimit, helpvalue ...string) Option {
	opt := s.VarLong((*unsigned)(p), name, short, helpvalue...)
	if l.Base > 36 || l.Base == 1 || l.Base < 0 {
		fmt.Fprintf(stderr, "invalid base for %s: %d\n", opt.Name(), l.Base)
		exit(1)
	}
	if l.Bits < 0 || l.Bits > 64 {
		fmt.Fprintf(stderr, "invalid bit size for %s: %d\n", opt.Name(), l.Bits)
		exit(1)
	}
	if l.Min > l.Max {
		fmt.Fprintf(stderr, "min greater than max for %s\n", opt.Name())
		exit(1)
	}
	lim := *l
	unsignedLimits[(*unsigned)(p)] = &lim
	return opt
}
