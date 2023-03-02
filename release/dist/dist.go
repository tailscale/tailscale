// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package dist is a release artifact builder library.
package dist

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"tailscale.com/util/multierr"
	"tailscale.com/version/mkversion"
)

// A Target is something that can be build in a Build.
type Target interface {
	String() string
	Build(build *Build) ([]string, error)
}

// A Build is a build context for Targets.
type Build struct {
	// Repo is a path to the root Go module for the build.
	Repo string
	// Out is where build artifacts are written.
	Out string
	// Verbose is whether to print all command output, rather than just failed
	// commands.
	Verbose bool

	// Tmp is a temporary directory that gets deleted when the Builder is closed.
	Tmp string
	// Go is the path to the Go binary to use for building.
	Go string
	// Version is the version info of the build.
	Version mkversion.VersionInfo

	// once is a cache of function invocations that should run once per process
	// (for example building a helper docker container)
	once once

	extraMu sync.Mutex
	extra   map[any]any

	goBuilds Memoize[string]
	// When running `dist build all` on a cold Go build cache, the fanout of
	// gooses and goarches results in a very large number of compile processes,
	// which bogs down the build machine.
	//
	// This throttles the number of concurrent `go build` invocations to the
	// number of CPU cores, which empirically keeps the builder responsive
	// without impacting overall build time.
	goBuildLimit chan struct{}
}

// NewBuild creates a new Build rooted at repo, and writing artifacts to out.
func NewBuild(repo, out string) (*Build, error) {
	if err := os.MkdirAll(out, 0750); err != nil {
		return nil, fmt.Errorf("creating out dir: %w", err)
	}
	tmp, err := os.MkdirTemp("", "dist-*")
	if err != nil {
		return nil, fmt.Errorf("creating tempdir: %w", err)
	}
	repo, err = findModRoot(repo)
	if err != nil {
		return nil, fmt.Errorf("finding module root: %w", err)
	}
	goTool, err := findGo(repo)
	if err != nil {
		return nil, fmt.Errorf("finding go binary: %w", err)
	}
	b := &Build{
		Repo:         repo,
		Tmp:          tmp,
		Out:          out,
		Go:           goTool,
		Version:      mkversion.Info(),
		extra:        map[any]any{},
		goBuildLimit: make(chan struct{}, runtime.NumCPU()),
	}

	return b, nil
}

// Close ends the build and cleans up temporary files.
func (b *Build) Close() error {
	return os.RemoveAll(b.Tmp)
}

// Build builds all targets concurrently.
func (b *Build) Build(targets []Target) (files []string, err error) {
	if len(targets) == 0 {
		return nil, errors.New("no targets specified")
	}
	log.Printf("Building %d targets: %v", len(targets), targets)
	var (
		wg         sync.WaitGroup
		errs       = make([]error, len(targets))
		buildFiles = make([][]string, len(targets))
	)
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t Target) {
			var err error
			defer func() {
				errs[i] = err
				wg.Done()
			}()
			fs, err := t.Build(b)
			buildFiles[i] = fs
		}(i, t)
	}
	wg.Wait()

	for _, fs := range buildFiles {
		files = append(files, fs...)
	}
	sort.Strings(files)

	return files, multierr.New(errs...)
}

// Once runs fn if Once hasn't been called with name before.
func (b *Build) Once(name string, fn func() error) error {
	return b.once.Do(name, fn)
}

// Extra returns a value from the build's extra state, creating it if necessary.
func (b *Build) Extra(key any, constructor func() any) any {
	b.extraMu.Lock()
	defer b.extraMu.Unlock()
	ret, ok := b.extra[key]
	if !ok {
		ret = constructor()
		b.extra[key] = ret
	}
	return ret
}

// GoPkg returns the path on disk of pkg.
// The module of pkg must be imported in b.Repo's go.mod.
func (b *Build) GoPkg(pkg string) (string, error) {
	out, err := b.Command(b.Repo, b.Go, "list", "-f", "{{.Dir}}", pkg).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("finding package %q: %w", pkg, err)
	}
	return strings.TrimSpace(out), nil
}

// TmpDir creates and returns a new empty temporary directory.
// The caller does not need to clean up the directory after use, it will get
// deleted by b.Close().
func (b *Build) TmpDir() string {
	// Because we're creating all temp dirs in our parent temp dir, the only
	// failures that can happen at this point are sequence breaks (e.g. if b.Tmp
	// is deleted while stuff is still running). So, panic on error to slightly
	// simplify callsites.
	ret, err := os.MkdirTemp(b.Tmp, "")
	if err != nil {
		panic(fmt.Sprintf("creating temp dir: %v", err))
	}
	return ret
}

// BuildGoBinary builds the Go binary at path and returns the path to the
// binary. Builds are cached by path and env, so each build only happens once
// per process execution.
func (b *Build) BuildGoBinary(path string, env map[string]string) (string, error) {
	err := b.Once("init-go", func() error {
		log.Printf("Initializing Go toolchain")
		// If the build is using a tool/go, it may need to download a toolchain
		// and do other initialization. Running `go version` once takes care of
		// all of that and avoids that initialization happening concurrently
		// later on in builds.
		_, err := b.Command(b.Repo, b.Go, "version").CombinedOutput()
		return err
	})
	if err != nil {
		return "", err
	}

	buildKey := []any{"go-build", path, env}
	return b.goBuilds.Do(buildKey, func() (string, error) {
		b.goBuildLimit <- struct{}{}
		defer func() { <-b.goBuildLimit }()

		var envStrs []string
		for k, v := range env {
			envStrs = append(envStrs, k+"="+v)
		}
		sort.Strings(envStrs)
		log.Printf("Building %s (with env %s)", path, strings.Join(envStrs, " "))
		buildDir := b.TmpDir()
		cmd := b.Command(b.Repo, b.Go, "build", "-v", "-o", buildDir, path)
		for k, v := range env {
			cmd.Cmd.Env = append(cmd.Cmd.Env, k+"="+v)
		}
		if err := cmd.Run(); err != nil {
			return "", err
		}
		out := filepath.Join(buildDir, filepath.Base(path))
		if env["GOOS"] == "windows" || env["GOOS"] == "windowsgui" {
			out += ".exe"
		}
		return out, nil
	})
}

// Command prepares an exec.Cmd to run [cmd, args...] in dir.
func (b *Build) Command(dir, cmd string, args ...string) *Command {
	ret := &Command{
		Cmd: exec.Command(cmd, args...),
	}
	if b.Verbose {
		ret.Cmd.Stdout = os.Stdout
		ret.Cmd.Stderr = os.Stderr
	} else {
		ret.Cmd.Stdout = &ret.Output
		ret.Cmd.Stderr = &ret.Output
	}
	// dist always wants to use gocross if any Go is involved.
	ret.Cmd.Env = append(os.Environ(), "TS_USE_GOCROSS=1")
	ret.Cmd.Dir = dir
	return ret
}

// Command runs an exec.Cmd and returns its exit status. If the command fails,
// its output is printed to os.Stdout, otherwise it's suppressed.
type Command struct {
	Cmd    *exec.Cmd
	Output bytes.Buffer
}

// Run is like c.Cmd.Run, but if the command fails, its output is printed to
// os.Stdout before returning the error.
func (c *Command) Run() error {
	err := c.Cmd.Run()
	if err != nil {
		// Command failed, dump its output.
		os.Stdout.Write(c.Output.Bytes())
	}
	return err
}

// CombinedOutput is like c.Cmd.CombinedOutput, but returns the output as a
// string instead of a byte slice.
func (c *Command) CombinedOutput() (string, error) {
	c.Cmd.Stdout = nil
	c.Cmd.Stderr = nil
	bs, err := c.Cmd.CombinedOutput()
	return string(bs), err
}

func findModRoot(path string) (string, error) {
	for {
		modpath := filepath.Join(path, "go.mod")
		if _, err := os.Stat(modpath); err == nil {
			return path, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		path = filepath.Dir(path)
		if path == "/" {
			return "", fmt.Errorf("no go.mod found in %q or any parent directory", path)
		}
	}
}

func findGo(path string) (string, error) {
	toolGo := filepath.Join(path, "tool/go")
	if _, err := os.Stat(toolGo); err == nil {
		return toolGo, nil
	}
	toolGo, err := exec.LookPath("go")
	if err != nil {
		return "", err
	}
	return toolGo, nil
}

// FilterTargets returns the subset of targets that match any of the filters.
// If filters is empty, returns all targets.
func FilterTargets(targets []Target, filters []string) ([]Target, error) {
	var filts []*regexp.Regexp
	for _, f := range filters {
		if f == "all" {
			return targets, nil
		}
		filt, err := regexp.Compile(f)
		if err != nil {
			return nil, fmt.Errorf("invalid filter %q: %w", f, err)
		}
		filts = append(filts, filt)
	}
	var ret []Target
	for _, t := range targets {
		for _, filt := range filts {
			if filt.MatchString(t.String()) {
				ret = append(ret, t)
				break
			}
		}
	}
	return ret, nil
}
