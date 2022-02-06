// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"fmt"
	"strings"
)

// An Option can be either a Flag or a Value
type Option interface {
	// Name returns the name of the option.  If the option has been seen
	// then the last way it was referenced (short or long) is returned
	// otherwise if there is a short name then this will be the short name
	// as a string, else it will be the long name.
	Name() string

	// IsFlag returns true if Option is a flag.
	IsFlag() bool

	// Seen returns true if the flag was seen.
	Seen() bool

	// Count returns the number of times the flag was seen.
	Count() int

	// String returns the last value the option was set to.
	String() string

	// Value returns the Value of the option.
	Value() Value

	// SetOptional makes the value optional.  The option and value are
	// always a single argument.  Either --option or --option=value.  In
	// the former case the value of the option does not change but the Set()
	// will return true and the value returned by Count() is incremented.
	// The short form is either -o or -ovalue.  SetOptional returns
	// the Option
	SetOptional() Option

	// SetFlag makes the value a flag.  Flags are boolean values and
	// normally do not taken a value.  They are set to true when seen.
	// If a value is passed in the long form then it must be on, case
	// insenstive, one of "true", "false", "t", "f", "on", "off", "1", "0".
	// SetFlag returns the Option
	SetFlag() Option

	// Reset resets the state of the option so it appears it has not
	// yet been seen, including resetting the value of the option
	// to its original default state.
	Reset()
}

type option struct {
	short    rune   // 0 means no short name
	long     string // "" means no long name
	isLong   bool   // True if they used the long name
	flag     bool   // true if a boolean flag
	defval   string // default value
	optional bool   // true if we take an optional value
	help     string // help message
	where    string // file where the option was defined
	value    Value  // current value of option
	count    int    // number of times we have seen this option
	name     string // name of the value (for usage)
	uname    string // name of the option (for usage)
}

// usageName returns the name of the option for printing usage lines in one
// of the following forms:
//
//  -f
//      --flag
//  -f, --flag
//  -s value
//      --set=value
//  -s, --set=value
func (o *option) usageName() string {
	// Don't print help messages if we have none and there is only one
	// way to specify the option.
	if o.help == "" && (o.short == 0 || o.long == "") {
		return ""
	}
	n := ""

	switch {
	case o.short != 0 && o.long == "":
		n = "-" + string(o.short)
	case o.short == 0 && o.long != "":
		n = "    --" + o.long
	case o.short != 0 && o.long != "":
		n = "-" + string(o.short) + ", --" + o.long
	}

	switch {
	case o.flag:
		return n
	case o.optional:
		return n + "[=" + o.name + "]"
	case o.long != "":
		return n + "=" + o.name
	}
	return n + " " + o.name
}

// sortName returns the name to sort the option on.
func (o *option) sortName() string {
	if o.short != 0 {
		return string(o.short) + o.long
	}
	return o.long[:1] + o.long
}

func (o *option) Seen() bool          { return o.count > 0 }
func (o *option) Count() int          { return o.count }
func (o *option) IsFlag() bool        { return o.flag }
func (o *option) String() string      { return o.value.String() }
func (o *option) SetOptional() Option { o.optional = true; return o }
func (o *option) SetFlag() Option     { o.flag = true; return o }

func (o *option) Value() Value {
	if o == nil {
		return nil
	}
	return o.value
}

func (o *option) Name() string {
	if !o.isLong && o.short != 0 {
		return "-" + string(o.short)
	}
	return "--" + o.long
}

// Reset rests an option so that it appears it has not yet been seen.
func (o *option) Reset() {
	o.isLong = false
	o.count = 0
	o.value.Set(o.defval, o)
}

type optionList []*option

func (ol optionList) Len() int      { return len(ol) }
func (ol optionList) Swap(i, j int) { ol[i], ol[j] = ol[j], ol[i] }
func (ol optionList) Less(i, j int) bool {
	// first check the short names (or the first letter of the long name)
	// If they are not equal (case insensitive) then we have our answer
	n1 := ol[i].sortName()
	n2 := ol[j].sortName()
	l1 := strings.ToLower(n1)
	l2 := strings.ToLower(n2)
	if l1 < l2 {
		return true
	}
	if l2 < l1 {
		return false
	}
	return n1 < n2
}

// AddOption add the option o to set CommandLine if o is not already in set
// CommandLine.
func AddOption(o Option) {
	CommandLine.AddOption(o)
}

// AddOption add the option o to set s if o is not already in set s.
func (s *Set) AddOption(o Option) {
	opt := o.(*option)
	for _, eopt := range s.options {
		if opt == eopt {
			return
		}
	}
	if opt.short != 0 {
		if oo, ok := s.shortOptions[opt.short]; ok {
			fmt.Fprintf(stderr, "%s: -%c already declared at %s\n", opt.where, opt.short, oo.where)
			exit(1)
		}
		s.shortOptions[opt.short] = opt
	}
	if opt.long != "" {
		if oo, ok := s.longOptions[opt.long]; ok {
			fmt.Fprintf(stderr, "%s: --%s already declared at %s\n", opt.where, opt.long, oo.where)
			exit(1)
		}
		s.longOptions[opt.long] = opt
	}
	s.options = append(s.options, opt)
}
