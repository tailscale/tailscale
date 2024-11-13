// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package cli contains the cmd/tailscale CLI code in a package that can be included
// in other wrapper binaries such as the Mac and Windows clients.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/envknob"
	"tailscale.com/paths"
	"tailscale.com/version/distro"
)

var Stderr io.Writer = os.Stderr
var Stdout io.Writer = os.Stdout

func errf(format string, a ...any) {
	fmt.Fprintf(Stderr, format, a...)
}

func printf(format string, a ...any) {
	fmt.Fprintf(Stdout, format, a...)
}

// outln is like fmt.Println in the common case, except when Stdout is
// changed (as in js/wasm).
//
// It's not named println because that looks like the Go built-in
// which goes to stderr and formats slightly differently.
func outln(a ...any) {
	fmt.Fprintln(Stdout, a...)
}

func newFlagSet(name string) *flag.FlagSet {
	onError := flag.ExitOnError
	if runtime.GOOS == "js" {
		onError = flag.ContinueOnError
	}
	fs := flag.NewFlagSet(name, onError)
	fs.SetOutput(Stderr)
	return fs
}

// CleanUpArgs rewrites command line arguments for simplicity and backwards compatibility.
// In particular, it rewrites --authkey to --auth-key.
func CleanUpArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		// Rewrite --authkey to --auth-key, and --authkey=x to --auth-key=x,
		// and the same for the -authkey variant.
		switch {
		case arg == "--authkey", arg == "-authkey":
			arg = "--auth-key"
		case strings.HasPrefix(arg, "--authkey="), strings.HasPrefix(arg, "-authkey="):
			arg = strings.TrimLeft(arg, "-")
			arg = strings.TrimPrefix(arg, "authkey=")
			arg = "--auth-key=" + arg
		}
		out = append(out, arg)
	}
	return out
}

var localClient = tailscale.LocalClient{
	Socket: paths.DefaultTailscaledSocket(),
}

// Run runs the CLI. The args do not include the binary name.
func Run(args []string) (err error) {
	if runtime.GOOS == "linux" && os.Getenv("GOKRAZY_FIRST_START") == "1" && distro.Get() == distro.Gokrazy && os.Getppid() == 1 {
		// We're running on gokrazy and it's the first start.
		// Don't run the tailscale CLI as a service; just exit.
		// See https://gokrazy.org/development/process-interface/
		os.Exit(0)
	}

	args = CleanUpArgs(args)

	if len(args) == 1 {
		switch args[0] {
		case "-V", "--version":
			args = []string{"version"}
		case "help":
			args = []string{"--help"}
		}
	}

	var warnOnce sync.Once
	tailscale.SetVersionMismatchHandler(func(clientVer, serverVer string) {
		warnOnce.Do(func() {
			fmt.Fprintf(Stderr, "Warning: client version %q != tailscaled server version %q\n", clientVer, serverVer)
		})
	})

	rootCmd := newRootCmd()
	if err := rootCmd.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		if noexec := (ffcli.NoExecError{}); errors.As(err, &noexec) {
			// When the user enters an unknown subcommand, ffcli tries to run
			// the closest valid parent subcommand with everything else as args,
			// returning NoExecError if it doesn't have an Exec function.
			cmd := noexec.Command
			args := cmd.FlagSet.Args()
			if len(cmd.Subcommands) > 0 {
				if len(args) > 0 {
					return fmt.Errorf("%s: unknown subcommand: %s", fullCmd(rootCmd, cmd), args[0])
				}
				subs := make([]string, 0, len(cmd.Subcommands))
				for _, sub := range cmd.Subcommands {
					subs = append(subs, sub.Name)
				}
				return fmt.Errorf("%s: missing subcommand: %s", fullCmd(rootCmd, cmd), strings.Join(subs, ", "))
			}
		}
		return err
	}

	if envknob.Bool("TS_DUMP_HELP") {
		walkCommands(rootCmd, func(w cmdWalk) bool {
			fmt.Println("===")
			// UsageFuncs are typically called during Command.Run which ensures
			// FlagSet is not nil.
			c := w.Command
			if c.FlagSet == nil {
				c.FlagSet = flag.NewFlagSet(c.Name, flag.ContinueOnError)
			}
			if c.UsageFunc != nil {
				fmt.Println(c.UsageFunc(c))
			} else {
				fmt.Println(ffcli.DefaultUsageFunc(c))
			}
			return true
		})
		return
	}

	err = rootCmd.Run(context.Background())
	if tailscale.IsAccessDeniedError(err) && os.Getuid() != 0 && runtime.GOOS != "windows" {
		return fmt.Errorf("%v\n\nUse 'sudo tailscale %s' or 'tailscale up --operator=$USER' to not require root.", err, strings.Join(args, " "))
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func newRootCmd() *ffcli.Command {
	rootfs := newFlagSet("tailscale")
	rootfs.Func("socket", "path to tailscaled socket", func(s string) error {
		localClient.Socket = s
		localClient.UseSocketOnly = true
		return nil
	})
	rootfs.Lookup("socket").DefValue = localClient.Socket

	rootCmd := &ffcli.Command{
		Name:       "tailscale",
		ShortUsage: "tailscale [flags] <subcommand> [command flags]",
		ShortHelp:  "The easiest, most secure way to use WireGuard.",
		LongHelp: strings.TrimSpace(`
For help on subcommands, add --help after: "tailscale status --help".

This CLI is still under active development. Commands and flags will
change in the future.
`),
		Subcommands: append([]*ffcli.Command{
			upCmd,
			downCmd,
			setCmd,
			loginCmd,
			logoutCmd,
			switchCmd,
			configureCmd,
			syspolicyCmd,
			netcheckCmd,
			ipCmd,
			dnsCmd,
			statusCmd,
			metricsCmd,
			pingCmd,
			ncCmd,
			sshCmd,
			funnelCmd(),
			serveCmd(),
			versionCmd,
			webCmd,
			fileCmd,
			bugReportCmd,
			certCmd,
			netlockCmd,
			licensesCmd,
			exitNodeCmd(),
			updateCmd,
			whoisCmd,
			debugCmd,
			driveCmd,
			idTokenCmd,
		}, maybeAdvertiseCmd()...),
		FlagSet: rootfs,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("tailscale: unknown subcommand: %s", args[0])
			}
			return flag.ErrHelp
		},
	}

	if runtime.GOOS == "linux" && distro.Get() == distro.Synology {
		rootCmd.Subcommands = append(rootCmd.Subcommands, configureHostCmd)
	}

	walkCommands(rootCmd, func(w cmdWalk) bool {
		if w.UsageFunc == nil {
			w.UsageFunc = usageFunc
		}
		return true
	})

	ffcomplete.Inject(rootCmd, func(c *ffcli.Command) { c.LongHelp = hidden + c.LongHelp }, usageFunc)
	return rootCmd
}

func fatalf(format string, a ...any) {
	if Fatalf != nil {
		Fatalf(format, a...)
		return
	}
	log.SetFlags(0)
	log.Fatalf(format, a...)
}

// Fatalf, if non-nil, is used instead of log.Fatalf.
var Fatalf func(format string, a ...any)

type cmdWalk struct {
	*ffcli.Command
	parents []*ffcli.Command
}

func (w cmdWalk) Path() string {
	if len(w.parents) == 0 {
		return w.Name
	}

	var sb strings.Builder
	for _, p := range w.parents {
		sb.WriteString(p.Name)
		sb.WriteString(" ")
	}
	sb.WriteString(w.Name)
	return sb.String()
}

// walkCommands calls f for root and all of its nested subcommands until f
// returns false or all have been visited.
func walkCommands(root *ffcli.Command, f func(w cmdWalk) (more bool)) {
	var walk func(cmd *ffcli.Command, parents []*ffcli.Command, f func(cmdWalk) bool) bool
	walk = func(cmd *ffcli.Command, parents []*ffcli.Command, f func(cmdWalk) bool) bool {
		if !f(cmdWalk{cmd, parents}) {
			return false
		}
		parents = append(parents, cmd)
		for _, sub := range cmd.Subcommands {
			if !walk(sub, parents, f) {
				return false
			}
		}
		return true
	}
	walk(root, nil, f)
}

// fullCmd returns the full "tailscale ... cmd" invocation for a subcommand.
func fullCmd(root, cmd *ffcli.Command) (full string) {
	walkCommands(root, func(w cmdWalk) bool {
		if w.Command == cmd {
			full = w.Path()
			return false
		}
		return true
	})
	if full == "" {
		return cmd.Name
	}
	return full
}

// usageFuncNoDefaultValues is like usageFunc but doesn't print default values.
func usageFuncNoDefaultValues(c *ffcli.Command) string {
	return usageFuncOpt(c, false)
}

func usageFunc(c *ffcli.Command) string {
	return usageFuncOpt(c, true)
}

// hidden is the prefix that hides subcommands and flags from --help output when
// found at the start of the subcommand's LongHelp or flag's Usage.
const hidden = "HIDDEN: "

func usageFuncOpt(c *ffcli.Command, withDefaults bool) string {
	var b strings.Builder

	if c.ShortHelp != "" {
		fmt.Fprintf(&b, "%s\n\n", c.ShortHelp)
	}

	fmt.Fprintf(&b, "USAGE\n")
	if c.ShortUsage != "" {
		fmt.Fprintf(&b, "  %s\n", strings.ReplaceAll(c.ShortUsage, "\n", "\n  "))
	} else {
		fmt.Fprintf(&b, "  %s\n", c.Name)
	}
	fmt.Fprintf(&b, "\n")

	if help := strings.TrimPrefix(c.LongHelp, hidden); help != "" {
		fmt.Fprintf(&b, "%s\n\n", help)
	}

	if len(c.Subcommands) > 0 {
		fmt.Fprintf(&b, "SUBCOMMANDS\n")
		tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
		for _, subcommand := range c.Subcommands {
			if strings.HasPrefix(subcommand.LongHelp, hidden) {
				continue
			}
			fmt.Fprintf(tw, "  %s\t%s\n", subcommand.Name, subcommand.ShortHelp)
		}
		tw.Flush()
		fmt.Fprintf(&b, "\n")
	}

	if countFlags(c.FlagSet) > 0 {
		fmt.Fprintf(&b, "FLAGS\n")
		tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
		c.FlagSet.VisitAll(func(f *flag.Flag) {
			var s string
			name, usage := flag.UnquoteUsage(f)
			if strings.HasPrefix(usage, hidden) {
				return
			}
			if isBoolFlag(f) {
				s = fmt.Sprintf("  --%s, --%s=false", f.Name, f.Name)
			} else {
				s = fmt.Sprintf("  --%s", f.Name) // Two spaces before --; see next two comments.
				if len(name) > 0 {
					s += " " + name
				}
			}
			// Four spaces before the tab triggers good alignment
			// for both 4- and 8-space tab stops.
			s += "\n    \t"
			s += strings.ReplaceAll(usage, "\n", "\n    \t")

			showDefault := f.DefValue != "" && withDefaults
			// Issue 6766: don't show the default Windows socket path. It's long
			// and distracting. And people on on Windows aren't likely to ever
			// change it anyway.
			if runtime.GOOS == "windows" && f.Name == "socket" && strings.HasPrefix(f.DefValue, `\\.\pipe\ProtectedPrefix\`) {
				showDefault = false
			}
			if showDefault {
				s += fmt.Sprintf(" (default %s)", f.DefValue)
			}

			fmt.Fprintln(&b, s)
		})
		tw.Flush()
		fmt.Fprintf(&b, "\n")
	}

	return strings.TrimSpace(b.String())
}

func isBoolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface {
		IsBoolFlag() bool
	})
	return ok && bf.IsBoolFlag()
}

func countFlags(fs *flag.FlagSet) (n int) {
	fs.VisitAll(func(*flag.Flag) { n++ })
	return n
}

// colorableOutput returns a colorable writer if stdout is a terminal (not, say,
// redirected to a file or pipe), the Stdout writer is os.Stdout (we're not
// embedding the CLI in wasm or a mobile app), and NO_COLOR is not set (see
// https://no-color.org/). If any of those is not the case, ok is false
// and w is Stdout.
func colorableOutput() (w io.Writer, ok bool) {
	if Stdout != os.Stdout ||
		os.Getenv("NO_COLOR") != "" ||
		!isatty.IsTerminal(os.Stdout.Fd()) {
		return Stdout, false
	}
	return colorable.NewColorableStdout(), true
}
