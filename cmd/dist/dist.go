// The dist command builds Tailscale release packages for distribution.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/release/dist"
	"tailscale.com/release/dist/unixpkgs"
)

func main() {
	var targets []dist.Target
	targets = append(targets, unixpkgs.Targets()...)
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].String() < targets[j].String()
	})

	rootCmd := &ffcli.Command{
		Name:       "dist",
		ShortUsage: "dist [flags] <command> [command flags]",
		ShortHelp:  "Build tailscale release packages for distribution",
		LongHelp:   `For help on subcommands, add --help after: "dist list --help".`,
		Subcommands: []*ffcli.Command{
			{
				Name: "list",
				Exec: func(ctx context.Context, args []string) error {
					return runList(ctx, args, targets)
				},
				ShortUsage: "dist list [target filters]",
				ShortHelp:  "List all available release targets.",
				LongHelp: strings.TrimSpace(`
			If filters are provided, only targets matching at least one filter are listed.
			Filters can use glob patterns (* and ?).
			`),
			},
			{
				Name: "build",
				Exec: func(ctx context.Context, args []string) error {
					return runBuild(ctx, args, targets)
				},
				ShortUsage: "dist build [target filters]",
				ShortHelp:  "Build release files",
				FlagSet: (func() *flag.FlagSet {
					fs := flag.NewFlagSet("build", flag.ExitOnError)
					fs.StringVar(&buildArgs.manifest, "manifest", "", "manifest file to write")
					return fs
				})(),
				LongHelp: strings.TrimSpace(`
			If filters are provided, only targets matching at least one filter are built.
			Filters can use glob patterns (* and ?).
			`),
			},
		},
		Exec: func(context.Context, []string) error { return flag.ErrHelp },
	}

	if err := rootCmd.ParseAndRun(context.Background(), os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}

func runList(ctx context.Context, filters []string, targets []dist.Target) error {
	tgts, err := dist.FilterTargets(targets, filters)
	if err != nil {
		return err
	}
	for _, tgt := range tgts {
		fmt.Println(tgt)
	}
	return nil
}

var buildArgs struct {
	manifest string
}

func runBuild(ctx context.Context, filters []string, targets []dist.Target) error {
	tgts, err := dist.FilterTargets(targets, filters)
	if err != nil {
		return err
	}
	if len(tgts) == 0 {
		return errors.New("no targets matched (did you mean 'dist build all'?)")
	}

	st := time.Now()
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}
	b, err := dist.NewBuild(wd, filepath.Join(wd, "dist"))
	if err != nil {
		return fmt.Errorf("creating build context: %w", err)
	}
	defer b.Close()

	out, err := b.Build(tgts)
	if err != nil {
		return fmt.Errorf("building targets: %w", err)
	}

	if buildArgs.manifest != "" {
		// Make the built paths relative to the manifest file.
		manifest, err := filepath.Abs(buildArgs.manifest)
		if err != nil {
			return fmt.Errorf("getting absolute path of manifest: %w", err)
		}
		fmt.Println(manifest)
		fmt.Println(filepath.Join(b.Out, out[0]))
		for i := range out {
			rel, err := filepath.Rel(filepath.Dir(manifest), filepath.Join(b.Out, out[i]))
			if err != nil {
				return fmt.Errorf("making path relative: %w", err)
			}
			out[i] = rel
		}
		if err := os.WriteFile(manifest, []byte(strings.Join(out, "\n")), 0644); err != nil {
			return fmt.Errorf("writing manifest: %w", err)
		}
	}

	fmt.Println("Done! Took", time.Since(st))
	return nil
}
