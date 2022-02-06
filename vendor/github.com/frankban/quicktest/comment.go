// Licensed under the MIT license, see LICENCE file for details.

package quicktest

import "fmt"

// Commentf returns a test comment whose output is formatted according to
// the given format specifier and args. It may be provided as the last argument
// to any check or assertion and will be displayed if the check or assertion
// fails. For instance:
//
//     c.Assert(a, qt.Equals, 42, qt.Commentf("answer is not %d", 42))
//
func Commentf(format string, args ...interface{}) Comment {
	return Comment{
		format: format,
		args:   args,
	}
}

// Comment represents additional information on a check or an assertion which is
// displayed when the check or assertion fails.
type Comment struct {
	format string
	args   []interface{}
}

// String outputs a string formatted according to the stored format specifier
// and args.
func (c Comment) String() string {
	return fmt.Sprintf(c.format, c.args...)
}
