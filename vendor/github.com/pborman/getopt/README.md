# getopt ![build status](https://travis-ci.org/pborman/getopt.svg?branch=master)

Package getopt provides traditional getopt processing for implementing
commands that use traditional command lines.  The standard Go flag package
cannot be used to write a program that parses flags the way ls or ssh does,
for example.  There are two versions, v1 and v2, both named getopt, that
use the following import paths:

```
	"github.com/pborman/getopt"     // version 1
	"github.com/pborman/getopt/v2"  // version 2
```

This README describes version 2 of the package, which has a simplified API.

## Usage

Getopt supports functionality found in both the standard BSD getopt as well
as (one of the many versions of) the GNU getopt_long.  Being a Go package,
this package makes common usage easy, but still enables more controlled usage
if needed.

Typical usage:

```
	Declare flags and have getopt return pointers to the values.
	helpFlag := getopt.Bool('?', "display help")
	cmdFlag := getopt.StringLong("command", 'c', "default", "the command")

	Declare flags against existing variables.
	var (
		fileName = "/the/default/path"
		timeout = time.Second * 5
		verbose bool
	)
	func init() {
		getopt.Flag(&verbose, 'v', "be verbose")
		getopt.FlagLong(&fileName, "path", 0, "the path")
		getopt.FlagLong(&timeout, "timeout", 't', "some timeout")
	}

	func main() {
		Parse the program arguments
		getopt.Parse()
		Get the remaining positional parameters
		args := getopt.Args()
		...
```

If you don't want the program to exit on error, use getopt.Getopt:

```
		err := getopt.Getopt(nil)
		if err != nil {
			code to handle error
			fmt.Fprintln(os.Stderr, err)
		}
```

## Flag Syntax

Support is provided for both short (-f) and long (--flag) options.  A single
option may have both a short and a long name.  Each option may be a flag or a
value.  A value takes an argument.

Declaring no long names causes this package to process arguments like the
traditional BSD getopt.

Short flags may be combined into a single parameter.  For example, "-a -b -c"
may also be expressed "-abc".  Long flags must stand on their own "--alpha
--beta"

Values require an argument.  For short options the argument may either be
immediately following the short name or as the next argument.  Only one short
value may be combined with short flags in a single argument; the short value
must be after all short flags.  For example, if f is a flag and v is a value,
then:

```
	-vvalue    (sets v to "value")
	-v value   (sets v to "value")
	-fvvalue   (sets f, and sets v to "value")
	-fv value  (sets f, and sets v to "value")
	-vf value  (set v to "f" and value is the first parameter)
```

For the long value option val:

```
	--val value (sets val to "value")
	--val=value (sets val to "value")
	--valvalue  (invalid option "valvalue")
```

Values with an optional value only set the value if the value is part of the
same argument.  In any event, the option count is increased and the option is
marked as seen.

```
	-v -f          (sets v and f as being seen)
	-vvalue -f     (sets v to "value" and sets f)
	--val -f       (sets v and f as being seen)
	--val=value -f (sets v to "value" and sets f)
```

There is no convience function defined for making the value optional.  The
SetOptional method must be called on the actual Option.

```
	v := String("val", 'v', "", "the optional v")
	Lookup("v").SetOptional()

	var s string
	FlagLong(&s, "val", 'v', "the optional v).SetOptional()
```

Parsing continues until the first non-option or "--" is encountered.

The short name "-" can be used, but it either is specified as "-" or as part
of a group of options, for example "-f-".  If there are no long options
specified then "--f" could also be used.  If "-" is not declared as an option
then the single "-" will also terminate the option processing but unlike
"--", the "-" will be part of the remaining arguments.

## Advanced Usage

Normally the parsing is performed by calling the Parse function.  If it is
important to see the order of the options then the Getopt function should be
used.  The standard Parse function does the equivalent of:

```
func Parse() {
	if err := getopt.Getopt(os.Args, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		s.usage()
		os.Exit(1)
	}
}
```

When calling Getopt it is the responsibility of the caller to print any
errors.

Normally the default option set, CommandLine, is used.  Other option sets may
be created with New.

After parsing, the sets Args will contain the non-option arguments.  If an
error is encountered then Args will begin with argument that caused the
error.

It is valid to call a set's Parse a second time to amend the current set of
flags or values.  As an example:

```
	var a = getopt.Bool('a', "", "The a flag")
	var b = getopt.Bool('b', "", "The a flag")
	var cmd = ""

	var opts = getopt.CommandLine

	opts.Parse(os.Args)
	if opts.NArgs() > 0 {
		cmd = opts.Arg(0)
		opts.Parse(opts.Args())
	}
```

If called with set to { "prog", "-a", "cmd", "-b", "arg" } then both a and
b would be set, cmd would be set to "cmd", and opts.Args() would return {
"arg" }.

Unless an option type explicitly prohibits it, an option may appear more than
once in the arguments.  The last value provided to the option is the value.

## Builtin Types

The Flag and FlagLong functions support most standard Go types.  For the
list, see the description of FlagLong below for a list of supported types.

There are also helper routines to allow single line flag declarations.  These
types are: Bool, Counter, Duration, Enum, Int16, Int32, Int64, Int, List,
Signed, String, Uint16, Uint32, Uint64, Uint, and Unsigned.

Each comes in a short and long flavor, e.g., Bool and BoolLong and include
functions to set the flags on the standard command line or for a specific Set
of flags.

Except for the Counter, Enum, Signed and Unsigned types, all of these types
can be declared using Flag and FlagLong by passing in a pointer to the
appropriate type.

## Declaring New Flag Types

A pointer to any type that implements the Value interface may be passed to
Flag or FlagLong.

## VALUEHELP

All non-flag options are created with a "valuehelp" as the last parameter.
Valuehelp should be 0, 1, or 2 strings.  The first string, if provided, is
the usage message for the option.  If the second string, if provided, is the
name to use for the value when displaying the usage.  If not provided the
term "value" is assumed.

The usage message for the option created with

```
	StringLong("option", 'o', "defval", "a string of letters")
```

is

```
	-o, -option=value
```
while the usage message for the option created with

```
	StringLong("option", 'o', "defval", "a string of letters", "string")
```

is

```
	-o, -option=string
```
