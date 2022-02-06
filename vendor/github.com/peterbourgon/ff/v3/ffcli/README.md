# ffcli [![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/peterbourgon/ff/v3/ffcli)

ffcli stands for flags-first command line interface,
and provides an opinionated way to build CLIs.

## Rationale

Popular CLI frameworks like [spf13/cobra][cobra], [urfave/cli][urfave], or
[alecthomas/kingpin][kingpin] tend to have extremely large APIs, to support a
large number of "table stakes" features.

[cobra]: https://github.com/spf13/cobra
[urfave]: https://github.com/urfave/cli
[kingpin]: https://github.com/alecthomas/kingpin

This package is intended to be a lightweight alternative to those packages. In
contrast to them, the API surface area of package ffcli is very small, with the
immediate goal of being intuitive and productive, and the long-term goal of
supporting commandline applications that are substantially easier to understand
and maintain.

To support these goals, the package is concerned only with the core mechanics of
defining a command tree, parsing flags, and selecting a command to run. It does
not intend to be a one-stop-shop for everything your commandline application
needs. Features like tab completion or colorized output are orthogonal to
command tree parsing, and should be easy to provide on top of ffcli.

Finally, this package follows in the philosophy of its parent package ff, or
"flags-first". Flags, and more specifically the Go stdlib flag.FlagSet, should
be the primary mechanism of getting configuration from the execution environment
into your program. The affordances provided by package ff, including environment
variable and config file parsing, are also available in package ffcli. Support
for other flag packages is a non-goal.


## Goals

- Absolute minimum usable API
- Prefer using existing language features/patterns/abstractions whenever possible
- Enable integration-style testing of CLIs with mockable dependencies
- No global state

## Non-goals

- All conceivably useful features
- Integration with flag packages other than [package flag][flag] and [ff][ff]

[flag]: https://golang.org/pkg/flag
[ff]: https://github.com/peterbourgon/ff

## Usage

The core of the package is the [ffcli.Command][command]. Here is the simplest
possible example of an ffcli program.

[command]: https://godoc.org/github.com/peterbourgon/ff/ffcli#Command

```go
import (
	"context"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func main() {
	root := &ffcli.Command{
		Exec: func(ctx context.Context, args []string) error {
			println("hello world")
			return nil
		},
	}

	root.ParseAndRun(context.Background(), os.Args[1:])
}
```

Most CLIs use flags and arguments to control behavior. Here is a command which
takes a string to repeat as an argument, and the number of times to repeat it as
a flag.

```go
fs := flag.NewFlagSet("repeat", flag.ExitOnError)
n := fs.Int("n", 3, "how many times to repeat")

root := &ffcli.Command{
	ShortUsage: "repeat [-n times] <arg>",
	ShortHelp:  "Repeatedly print the argument to stdout.",
	FlagSet:    fs,
	Exec: func(ctx context.Context, args []string) error {
		if nargs := len(args); nargs != 1 {
			return fmt.Errorf("repeat requires exactly 1 argument, but you provided %d", nargs)
		}
		for i := 0; i < *n; i++ {
			fmt.Fprintln(os.Stdout, args[0])
		}
		return nil
	},
}

if err := root.ParseAndRun(context.Background(), os.Args[1:]); err != nil {
	log.Fatal(err)
}
```

Each command may have subcommands, allowing you to build a command tree.

```go
var (
	rootFlagSet   = flag.NewFlagSet("textctl", flag.ExitOnError)
	verbose       = rootFlagSet.Bool("v", false, "increase log verbosity")
	repeatFlagSet = flag.NewFlagSet("textctl repeat", flag.ExitOnError)
	n             = repeatFlagSet.Int("n", 3, "how many times to repeat")
)

repeat := &ffcli.Command{
	Name:       "repeat",
	ShortUsage: "textctl repeat [-n times] <arg>",
	ShortHelp:  "Repeatedly print the argument to stdout.",
	FlagSet:    repeatFlagSet,
	Exec:       func(_ context.Context, args []string) error { ... },
}

count := &ffcli.Command{
	Name:       "count",
	ShortUsage: "textctl count [<arg> ...]",
	ShortHelp:  "Count the number of bytes in the arguments.",
	Exec:       func(_ context.Context, args []string) error { ... },
}

root := &ffcli.Command{
	ShortUsage:  "textctl [flags] <subcommand>",
	FlagSet:     rootFlagSet,
	Subcommands: []*ffcli.Command{repeat, count},
}

if err := root.ParseAndRun(context.Background(), os.Args[1:]); err != nil {
	log.Fatal(err)
}
```

ParseAndRun can also be split into distinct Parse and Run phases, allowing you
to perform two-phase setup or initialization of e.g. API clients that require
user-supplied configuration.

## Examples

See [the examples directory][examples]. If you'd like an example of a specific
type of program structure, or a CLI that satisfies a specific requirement,
please [file an issue][issue].

[examples]: https://github.com/peterbourgon/ff/tree/master/ffcli/examples
[issue]: https://github.com/peterbourgon/ff/issues/new
