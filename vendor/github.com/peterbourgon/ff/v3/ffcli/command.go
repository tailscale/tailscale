package ffcli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3"
)

// Command combines a main function with a flag.FlagSet, and zero or more
// sub-commands. A commandline program can be represented as a declarative tree
// of commands.
type Command struct {
	// Name of the command. Used for sub-command matching, and as a replacement
	// for Usage, if no Usage string is provided. Required for sub-commands,
	// optional for the root command.
	Name string

	// ShortUsage string for this command. Consumed by the DefaultUsageFunc and
	// printed at the top of the help output. Recommended but not required.
	// Should be one line of the form
	//
	//     cmd [flags] subcmd [flags] <required> [<optional> ...]
	//
	// If it's not provided, the DefaultUsageFunc will use Name instead.
	// Optional, but recommended.
	ShortUsage string

	// ShortHelp is printed next to the command name when it appears as a
	// sub-command, in the help output of its parent command. Optional, but
	// recommended.
	ShortHelp string

	// LongHelp is consumed by the DefaultUsageFunc and printed in the help
	// output, after ShortUsage and before flags. Typically a paragraph or more
	// of prose-like text, providing more explicit context and guidance than
	// what is implied by flags and arguments. Optional.
	LongHelp string

	// UsageFunc generates a complete usage output, written to the io.Writer
	// returned by FlagSet.Output() when the -h flag is passed. The function is
	// invoked with its corresponding command, and its output should reflect the
	// command's short usage, short help, and long help strings, subcommands,
	// and available flags. Optional; if not provided, a suitable, compact
	// default is used.
	UsageFunc func(c *Command) string

	// FlagSet associated with this command. Optional, but if none is provided,
	// an empty FlagSet will be defined and attached during the parse phase, so
	// that the -h flag works as expected.
	FlagSet *flag.FlagSet

	// Options provided to ff.Parse when parsing arguments for this command.
	// Optional.
	Options []ff.Option

	// Subcommands accessible underneath (i.e. after) this command. Optional.
	Subcommands []*Command

	// A successful Parse populates these unexported fields.
	selected *Command // the command itself (if terminal) or a subcommand
	args     []string // args that should be passed to Run, if any

	// Exec is invoked if this command has been determined to be the terminal
	// command selected by the arguments provided to Parse or ParseAndRun. The
	// args passed to Exec are the args left over after flags parsing. Optional.
	//
	// If Exec returns flag.ErrHelp, then Run (or ParseAndRun) will behave as if
	// -h were passed and emit the complete usage output.
	//
	// If Exec is nil, and this command is identified as the terminal command,
	// then Parse, Run, and ParseAndRun will all return NoExecError. Callers may
	// check for this error and print e.g. help or usage text to the user, in
	// effect treating some commands as just collections of subcommands, rather
	// than being invocable themselves.
	Exec func(ctx context.Context, args []string) error
}

// Parse the commandline arguments for this command and all sub-commands
// recursively, defining flags along the way. If Parse returns without an error,
// the terminal command has been successfully identified, and may be invoked by
// calling Run.
//
// If the terminal command identified by Parse doesn't define an Exec function,
// then Parse will return NoExecError.
func (c *Command) Parse(args []string) error {
	if c.selected != nil {
		return nil
	}

	if c.FlagSet == nil {
		c.FlagSet = flag.NewFlagSet(c.Name, flag.ExitOnError)
	}

	if c.UsageFunc == nil {
		c.UsageFunc = DefaultUsageFunc
	}

	c.FlagSet.Usage = func() {
		fmt.Fprintln(c.FlagSet.Output(), c.UsageFunc(c))
	}

	if err := ff.Parse(c.FlagSet, args, c.Options...); err != nil {
		return err
	}

	c.args = c.FlagSet.Args()
	if len(c.args) > 0 {
		for _, subcommand := range c.Subcommands {
			if strings.EqualFold(c.args[0], subcommand.Name) {
				c.selected = subcommand
				return subcommand.Parse(c.args[1:])
			}
		}
	}

	c.selected = c

	if c.Exec == nil {
		return NoExecError{Command: c}
	}

	return nil
}

// Run selects the terminal command in a command tree previously identified by a
// successful call to Parse, and calls that command's Exec function with the
// appropriate subset of commandline args.
//
// If the terminal command previously identified by Parse doesn't define an Exec
// function, then Run will return NoExecError.
func (c *Command) Run(ctx context.Context) (err error) {
	var (
		unparsed = c.selected == nil
		terminal = c.selected == c && c.Exec != nil
		noop     = c.selected == c && c.Exec == nil
	)

	defer func() {
		if terminal && errors.Is(err, flag.ErrHelp) {
			c.FlagSet.Usage()
		}
	}()

	switch {
	case unparsed:
		return ErrUnparsed
	case terminal:
		return c.Exec(ctx, c.args)
	case noop:
		return NoExecError{Command: c}
	default:
		return c.selected.Run(ctx)
	}
}

// ParseAndRun is a helper function that calls Parse and then Run in a single
// invocation. It's useful for simple command trees that don't need two-phase
// setup.
func (c *Command) ParseAndRun(ctx context.Context, args []string) error {
	if err := c.Parse(args); err != nil {
		return err
	}

	if err := c.Run(ctx); err != nil {
		return err
	}

	return nil
}

//
//
//

// ErrUnparsed is returned by Run if Parse hasn't been called first.
var ErrUnparsed = errors.New("command tree is unparsed, can't run")

// NoExecError is returned if the terminal command selected during the parse
// phase doesn't define an Exec function.
type NoExecError struct {
	Command *Command
}

// Error implements the error interface.
func (e NoExecError) Error() string {
	return fmt.Sprintf("terminal command (%s) doesn't define an Exec function", e.Command.Name)
}

//
//
//

// DefaultUsageFunc is the default UsageFunc used for all commands
// if no custom UsageFunc is provided.
func DefaultUsageFunc(c *Command) string {
	var b strings.Builder

	fmt.Fprintf(&b, "USAGE\n")
	if c.ShortUsage != "" {
		fmt.Fprintf(&b, "  %s\n", c.ShortUsage)
	} else {
		fmt.Fprintf(&b, "  %s\n", c.Name)
	}
	fmt.Fprintf(&b, "\n")

	if c.LongHelp != "" {
		fmt.Fprintf(&b, "%s\n\n", c.LongHelp)
	}

	if len(c.Subcommands) > 0 {
		fmt.Fprintf(&b, "SUBCOMMANDS\n")
		tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
		for _, subcommand := range c.Subcommands {
			fmt.Fprintf(tw, "  %s\t%s\n", subcommand.Name, subcommand.ShortHelp)
		}
		tw.Flush()
		fmt.Fprintf(&b, "\n")
	}

	if countFlags(c.FlagSet) > 0 {
		fmt.Fprintf(&b, "FLAGS\n")
		tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
		c.FlagSet.VisitAll(func(f *flag.Flag) {
			space := " "
			if isBoolFlag(f) {
				space = "="
			}

			def := f.DefValue
			if def == "" {
				def = "..."
			}

			fmt.Fprintf(tw, "  -%s%s%s\t%s\n", f.Name, space, def, f.Usage)
		})
		tw.Flush()
		fmt.Fprintf(&b, "\n")
	}

	return strings.TrimSpace(b.String()) + "\n"
}

func countFlags(fs *flag.FlagSet) (n int) {
	fs.VisitAll(func(*flag.Flag) { n++ })
	return n
}

func isBoolFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface {
		IsBoolFlag() bool
	})
	return ok && b.IsBoolFlag()
}
