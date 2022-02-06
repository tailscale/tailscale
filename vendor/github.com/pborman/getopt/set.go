// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import (
	"io"
	"os"
	"sort"
)

// A Termination says why Getopt returned.
type State int

const (
	InProgress     = State(iota) // Getopt is still running
	Dash                         // Returned on "-"
	DashDash                     // Returned on "--"
	EndOfOptions                 // End of options reached
	EndOfArguments               // No more arguments
	Terminated                   // Terminated by callback function
	Failure                      // Terminated due to error
	Unknown                      // Indicates internal error
)

type Set struct {
	State // State of getopt

	// args are the parameters remaining after parsing the optoins.
	args []string

	// program is the name of the program for usage and error messages.
	// If not set it will automatically be set to the base name of the
	// first argument passed to parse.
	program string

	// parameters is what is displayed on the usage line after displaying
	// the various options.
	parameters string

	usage func() // usage should print the programs usage and exit.

	shortOptions map[rune]*option
	longOptions  map[string]*option
	options      optionList
}

// New returns a newly created option set.
func New() *Set {
	s := &Set{
		shortOptions: make(map[rune]*option),
		longOptions:  make(map[string]*option),
		parameters:   "[parameters ...]",
	}

	s.usage = func() {
		s.PrintUsage(stderr)
	}
	return s
}

// The default set of command-line options.
var CommandLine = New()

// PrintUsage calls PrintUsage in the default option set.
func PrintUsage(w io.Writer) { CommandLine.PrintUsage(w) }

// Usage calls the usage function in the default option set.
func Usage() { CommandLine.usage() }

// Parse calls Parse in the default option set with the command line arguments
// found in os.Args.
func Parse() { CommandLine.Parse(os.Args) }

// Getops returns the result of calling Getop in the default option set with the
// command line arguments found in os.Args.  The fn function, which may be nil,
// is passed to Getopt.
func Getopt(fn func(Option) bool) error { return CommandLine.Getopt(os.Args, fn) }

// Arg returns the n'th command-line argument. Arg(0) is the first remaining
// argument after options have been processed.
func Arg(n int) string {
	if n >= 0 && n < len(CommandLine.args) {
		return CommandLine.args[n]
	}
	return ""
}

// Arg returns the n'th argument. Arg(0) is the first remaining
// argument after options have been processed.
func (s *Set) Arg(n int) string {
	if n >= 0 && n < len(s.args) {
		return s.args[n]
	}
	return ""
}

// Args returns the non-option command line arguments.
func Args() []string {
	return CommandLine.args
}

// Args returns the non-option arguments.
func (s *Set) Args() []string {
	return s.args
}

// NArgs returns the number of non-option command line arguments.
func NArgs() int {
	return len(CommandLine.args)
}

// NArgs returns the number of non-option arguments.
func (s *Set) NArgs() int {
	return len(s.args)
}

// SetParameters sets the parameters string for printing the command line
// usage.  It defaults to "[parameters ...]"
func SetParameters(parameters string) {
	CommandLine.parameters = parameters
}

// SetParameters sets the parameters string for printing the s's usage.
// It defaults to "[parameters ...]"
func (s *Set) SetParameters(parameters string) {
	s.parameters = parameters
}

// SetProgram sets the program name to program.  Nomrally it is determined
// from the zeroth command line argument (see os.Args).
func SetProgram(program string) {
	CommandLine.program = program
}

// SetProgram sets s's program name to program.  Nomrally it is determined
// from the zeroth argument passed to Getopt or Parse.
func (s *Set) SetProgram(program string) {
	s.program = program
}

// SetUsage sets the function used by Parse to display the commands usage
// on error.  It defaults to calling PrintUsage(os.Stderr).
func SetUsage(usage func()) {
	CommandLine.usage = usage
}

// SetUsage sets the function used by Parse to display usage on error.  It
// defaults to calling f.PrintUsage(os.Stderr).
func (s *Set) SetUsage(usage func()) {
	s.usage = usage
}

// Lookup returns the Option associated with name.  Name should either be
// a rune (the short name) or a string (the long name).
func Lookup(name interface{}) Option {
	return CommandLine.Lookup(name)
}

// Lookup returns the Option associated with name in s.  Name should either be
// a rune (the short name) or a string (the long name).
func (s *Set) Lookup(name interface{}) Option {
	switch v := name.(type) {
	case rune:
		return s.shortOptions[v]
	case int:
		return s.shortOptions[rune(v)]
	case string:
		return s.longOptions[v]
	}
	return nil
}

// IsSet returns true if the Option associated with name was seen while
// parsing the command line arguments.  Name should either be a rune (the
// short name) or a string (the long name).
func IsSet(name interface{}) bool {
	return CommandLine.IsSet(name)
}

// IsSet returns true if the Option associated with name was seen while
// parsing s.  Name should either be a rune (the short name) or a string (the
// long name).
func (s *Set) IsSet(name interface{}) bool {
	if opt := s.Lookup(name); opt != nil {
		return opt.Seen()
	}
	return false
}

// GetCount returns the number of times the Option associated with name has been
// seen while parsing the command line arguments.  Name should either be a rune
// (the short name) or a string (the long name).
func GetCount(name interface{}) int {
	return CommandLine.GetCount(name)
}

// GetCount returns the number of times the Option associated with name has been
// seen while parsing s's arguments.  Name should either be a rune (the short
// name) or a string (the long name).
func (s *Set) GetCount(name interface{}) int {
	if opt := s.Lookup(name); opt != nil {
		return opt.Count()
	}
	return 0
}

// GetValue returns the final value set to the command-line Option with name.
// If the option has not been seen while parsing s then the default value is
// returned.  Name should either be a rune (the short name) or a string (the
// long name).
func GetValue(name interface{}) string {
	return CommandLine.GetValue(name)
}

// GetValue returns the final value set to the Option in s associated with name.
// If the option has not been seen while parsing s then the default value is
// returned.  Name should either be a rune (the short name) or a string (the
// long name).
func (s *Set) GetValue(name interface{}) string {
	if opt := s.Lookup(name); opt != nil {
		return opt.String()
	}
	return ""
}

// Visit visits the command-line options in lexicographical order, calling fn
// for each. It visits only those options that have been set.
func Visit(fn func(Option)) { CommandLine.Visit(fn) }

// Visit visits the options in s in lexicographical order, calling fn
// for each. It visits only those options that have been set.
func (s *Set) Visit(fn func(Option)) {
	sort.Sort(s.options)
	for _, opt := range s.options {
		if opt.count > 0 {
			fn(opt)
		}
	}
}

// VisitAll visits the options in s in lexicographical order, calling fn
// for each. It visits all options, even those not set.
func VisitAll(fn func(Option)) { CommandLine.VisitAll(fn) }

// VisitAll visits the command-line flags in lexicographical order, calling fn
// for each. It visits all flags, even those not set.
func (s *Set) VisitAll(fn func(Option)) {
	sort.Sort(s.options)
	for _, opt := range s.options {
		fn(opt)
	}
}

// Reset resets all the command line options to the initial state so it
// appears none of them have been seen.
func Reset() {
	CommandLine.Reset()
}

// Reset resets all the options in s to the initial state so it
// appears none of them have been seen.
func (s *Set) Reset() {
	for _, opt := range s.options {
		opt.Reset()
	}
}
