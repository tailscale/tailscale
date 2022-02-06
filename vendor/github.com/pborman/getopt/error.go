// Copyright 2013 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package getopt

import "fmt"

// An Error is returned by Getopt when it encounters an error.
type Error struct {
	ErrorCode        // General reason of failure.
	Err       error  // The actual error.
	Parameter string // Parameter passed to option, if any
	Name      string // Option that cause error, if any
}

// Error returns the error message, implementing the error interface.
func (i *Error) Error() string { return i.Err.Error() }

// An ErrorCode indicates what sort of error was encountered.
type ErrorCode int

const (
	NoError          = ErrorCode(iota)
	UnknownOption    // an invalid option was encountered
	MissingParameter // the options parameter is missing
	ExtraParameter   // a value was set to a long flag
	Invalid          // attempt to set an invalid value
)

func (e ErrorCode) String() string {
	switch e {
	case UnknownOption:
		return "unknow option"
	case MissingParameter:
		return "missing argument"
	case ExtraParameter:
		return "unxpected value"
	case Invalid:
		return "error setting value"
	}
	return "unknown error"
}

// unknownOption returns an Error indicating an unknown option was
// encountered.
func unknownOption(name interface{}) *Error {
	i := &Error{ErrorCode: UnknownOption}
	switch n := name.(type) {
	case rune:
		if n == '-' {
			i.Name = "-"
		} else {
			i.Name = "-" + string(n)
		}
	case string:
		i.Name = "--" + n
	}
	i.Err = fmt.Errorf("unknown option: %s", i.Name)
	return i
}

// missingArg returns an Error inidicating option o was not passed
// a required paramter.
func missingArg(o Option) *Error {
	return &Error{
		ErrorCode: MissingParameter,
		Name:      o.Name(),
		Err:       fmt.Errorf("missing parameter for %s", o.Name()),
	}
}

// extraArg returns an Error inidicating option o was passed the
// unexpected paramter value.
func extraArg(o Option, value string) *Error {
	return &Error{
		ErrorCode: ExtraParameter,
		Name:      o.Name(),
		Parameter: value,
		Err:       fmt.Errorf("unexpected parameter passed to %s: %q", o.Name(), value),
	}
}

// setError returns an Error inidicating option o and the specified
// error while setting it to value.
func setError(o Option, value string, err error) *Error {
	return &Error{
		ErrorCode: Invalid,
		Name:      o.Name(),
		Parameter: value,
		Err:       err,
	}
}
