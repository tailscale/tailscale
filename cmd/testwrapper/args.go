// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"flag"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// registerTestFlags registers all flags from the testing package with the
// provided flag set. It does so by calling testing.Init() and then iterating
// over all flags registered on flag.CommandLine.
func registerTestFlags(fs *flag.FlagSet) {
	testing.Init()
	type bv interface {
		IsBoolFlag() bool
	}

	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if b, ok := f.Value.(bv); ok && b.IsBoolFlag() {
			fs.Bool(f.Name, f.DefValue == "true", f.Usage)
			if name, ok := strings.CutPrefix(f.Name, "test."); ok {
				fs.Bool(name, f.DefValue == "true", f.Usage)
			}
			return
		}

		// We don't actually care about the value of the flag, so we just
		// register it as a string. The values will be passed to `go test` which
		// will parse and validate them anyway.
		fs.String(f.Name, f.DefValue, f.Usage)
		if name, ok := strings.CutPrefix(f.Name, "test."); ok {
			fs.String(name, f.DefValue, f.Usage)
		}
	})
}

// splitArgs splits args into three parts as consumed by go test.
//
//	go test [build/test flags] [packages] [build/test flags & test binary flags]
//
// We return these as three slices of strings [pre] [pkgs] [post].
//
// It is used to split the arguments passed to testwrapper into the arguments
// passed to go test and the arguments passed to the tests.
func splitArgs(args []string) (pre, pkgs, post []string, _ error) {
	if len(args) == 0 {
		return nil, nil, nil, nil
	}

	fs := newTestFlagSet()
	// Parse stops at the first non-flag argument, so this allows us
	// to parse those as values and then reconstruct them as args.
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "cachelink" && !cacheLink.enabled {
			return
		}
		if f.Value.String() != f.DefValue && f.DefValue != "false" {
			pre = append(pre, "-"+f.Name, f.Value.String())
		} else {
			pre = append(pre, "-"+f.Name)
		}
	})

	// fs.Args() now contains [packages]+[build/test flags & test binary flags],
	// to split it we need to find the first non-flag argument.
	rem := fs.Args()
	ix := slices.IndexFunc(rem, func(s string) bool { return strings.HasPrefix(s, "-") })
	if ix == -1 {
		return pre, rem, nil, nil
	}
	pkgs = rem[:ix]
	post = rem[ix:]
	return pre, pkgs, post, nil
}

// cacheLink is whether the -cachelink flag is enabled.
//
// The -cachelink flag is Tailscale-specific addition to the "go test" command;
// see https://github.com/tailscale/go/issues/149 and
// https://github.com/golang/go/issues/77349.
//
// In that PR, it's only a boolean, but we implement a custom flag type
// so we can support -cachelink=auto, which enables cachelink if GOCACHEPROG
// is set, which is a behavior we want in our CI environment.
var cacheLink cacheLinkVal

type cacheLinkVal struct {
	enabled bool
}

func (c *cacheLinkVal) String() string {
	return strconv.FormatBool(c.enabled)
}

func (c *cacheLinkVal) Set(s string) error {
	if s == "auto" {
		c.enabled = os.Getenv("GOCACHEPROG") != ""
		return nil
	}
	var err error
	c.enabled, err = strconv.ParseBool(s)
	return err
}

func (*cacheLinkVal) IsBoolFlag() bool { return true }

func newTestFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("testwrapper", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	// Register all flags from the testing package.
	registerTestFlags(fs)
	// Also register the -exec flag, which is not part of the testing package.
	// TODO(maisem): figure out what other flags we need to register explicitly.
	fs.String("exec", "", "Command to run tests with")
	fs.Bool("race", false, "build with race detector")
	fs.String("vet", "", "vet checks to run, or 'off' or 'all'")

	fs.Var(&cacheLink, "cachelink", "Go -cachelink value (bool); or 'auto' to enable if GOCACHEPROG is set")
	return fs
}

// testingVerbose reports whether the test is being run with verbose logging.
var testingVerbose = func() bool {
	verbose := false

	// Likely doesn't matter, but to be correct follow the go flag parsing logic
	// of overriding previous values.
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-test.v", "--test.v",
			"-test.v=true", "--test.v=true",
			"-v", "--v",
			"-v=true", "--v=true":
			verbose = true
		case "-test.v=false", "--test.v=false",
			"-v=false", "--v=false":
			verbose = false
		}
	}
	return verbose
}()
