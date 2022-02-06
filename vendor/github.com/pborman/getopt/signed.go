// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strconv"
)

type signed int64

type SignedLimit struct {
	Base int   // Base for conversion as per strconv.ParseInt
	Bits int   // Number of bits as per strconv.ParseInt
	Min  int64 // Minimum allowed value if both Min and Max are not 0
	Max  int64 // Maximum allowed value if both Min and Max are not 0
}

var signedLimits = make(map[*signed]*SignedLimit)

func (n *signed) Set(value string, opt Option) error {
	l := signedLimits[n]
	if l == nil {
		return fmt.Errorf("no limits defined for %s", opt.Name())
	}
	v, err := strconv.ParseInt(value, l.Base, l.Bits)
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
	*n = signed(v)
	return nil
}

func (n *signed) String() string {
	l := signedLimits[n]
	if l != nil && l.Base != 0 {
		return strconv.FormatInt(int64(*n), l.Base)
	}
	return strconv.FormatInt(int64(*n), 10)
}

// Signed creates an option that is stored in an int64 and is constrained
// by the limits pointed to by l.  The Max and Min values are only used if
// at least one of the values are not 0.   If Base is 0, the base is implied by
// the string's prefix: base 16 for "0x", base 8 for "0", and base 10 otherwise.
func Signed(name rune, value int64, l *SignedLimit, helpvalue ...string) *int64 {
	return CommandLine.Signed(name, value, l, helpvalue...)
}

func (s *Set) Signed(name rune, value int64, l *SignedLimit, helpvalue ...string) *int64 {
	return s.SignedLong("", name, value, l, helpvalue...)
}

func SignedLong(name string, short rune, value int64, l *SignedLimit, helpvalue ...string) *int64 {
	return CommandLine.SignedLong(name, short, value, l, helpvalue...)
}

func (s *Set) SignedLong(name string, short rune, value int64, l *SignedLimit, helpvalue ...string) *int64 {
	s.SignedVarLong(&value, name, short, l, helpvalue...)
	return &value
}

func SignedVar(p *int64, name rune, l *SignedLimit, helpvalue ...string) Option {
	return CommandLine.SignedVar(p, name, l, helpvalue...)
}

func (s *Set) SignedVar(p *int64, name rune, l *SignedLimit, helpvalue ...string) Option {
	return s.SignedVarLong(p, "", name, l, helpvalue...)
}

func SignedVarLong(p *int64, name string, short rune, l *SignedLimit, helpvalue ...string) Option {
	return CommandLine.SignedVarLong(p, name, short, l, helpvalue...)
}

func (s *Set) SignedVarLong(p *int64, name string, short rune, l *SignedLimit, helpvalue ...string) Option {
	opt := s.VarLong((*signed)(p), name, short, helpvalue...)
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
	signedLimits[(*signed)(p)] = &lim
	return opt
}
