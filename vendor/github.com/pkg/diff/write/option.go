// Package write provides routines for writing diffs.
package write

// An Option modifies behavior when writing a diff.
type Option interface {
	isOption()
}

// Names provides the before/after names for writing a diff.
// They are traditionally filenames.
func Names(a, b string) Option {
	return names{a, b}
}

type names struct {
	a, b string
}

func (names) isOption() {}

// TerminalColor specifies that a diff intended
// for a terminal should be written using colors.
//
// Do not use TerminalColor if TERM=dumb is set in the environment.
func TerminalColor() Option {
	return colorOpt(true)
}

type colorOpt bool

func (colorOpt) isOption() {}

const (
	ansiBold    = "\u001b[1m"
	ansiFgRed   = "\u001b[31m"
	ansiFgGreen = "\u001b[32m"
	ansiFgBlue  = "\u001b[36m"
	ansiReset   = "\u001b[0m"
)
