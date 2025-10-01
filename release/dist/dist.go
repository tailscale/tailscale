// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package dist is a release artifact builder library.
package dist

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/version/mkversion"
)

// A Target is something that can be build in a Build.
type Target interface {
	String() string
	Build(build *Build) ([]string, error)
}

// Signer is pluggable signer for a Target.
type Signer func(io.Reader) ([]byte, error)

// SignFile signs the file at filePath with s and writes the signature to
// sigPath.
func (s Signer) SignFile(filePath, sigPath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	sig, err := s(f)
	if err != nil {
		return err
	}
	return os.WriteFile(sigPath, sig, 0644)
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
	// WebClientSource is a path to the source for the web client.
	// If non-empty, web client assets will be built.
	WebClientSource string

	// Tmp is a temporary directory that gets deleted when the Builder is closed.
	Tmp string
	// Go is the path to the Go binary to use for building.
	Go string
	// Yarn is the path to the yarn binary to use for building the web client assets.
	Yarn string
	// Version is the version info of the build.
	Version mkversion.VersionInfo
	// Time is the timestamp of the build.
	Time time.Time

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

	onCloseFuncs []func() error // funcs to be called when Builder is closed
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
	goTool, err := findTool(repo, "go")
	if err != nil {
		return nil, fmt.Errorf("finding go binary: %w", err)
	}
	yarnTool, err := findTool(repo, "yarn")
	if err != nil {
		return nil, fmt.Errorf("finding yarn binary: %w", err)
	}
	b := &Build{
		Repo:         repo,
		Tmp:          tmp,
		Out:          out,
		Go:           goTool,
		Yarn:         yarnTool,
		Version:      mkversion.Info(),
		Time:         time.Now().UTC(),
		extra:        map[any]any{},
		goBuildLimit: make(chan struct{}, runtime.NumCPU()),
	}

	return b, nil
}

func (b *Build) AddOnCloseFunc(f func() error) {
	b.onCloseFuncs = append(b.onCloseFuncs, f)
}

// Close ends the build, cleans up temporary files,
// and runs any onCloseFuncs.
func (b *Build) Close() error {
	var errs []error
	errs = append(errs, os.RemoveAll(b.Tmp))
	for _, f := range b.onCloseFuncs {
		errs = append(errs, f())
	}
	return errors.Join(errs...)
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
				if err != nil {
					err = fmt.Errorf("%s: %w", t, err)
				}
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

	return files, errors.Join(errs...)
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

// BuildWebClientAssets builds the JS and CSS assets used by the web client.
// If b.WebClientSource is non-empty, assets are built in a "build" sub-directory of that path.
// Otherwise, no assets are built.
func (b *Build) BuildWebClientAssets() error {
	// Nothing in the web client assets is platform-specific,
	// so we only need to build it once.
	return b.Once("build-web-client-assets", func() error {
		if b.WebClientSource == "" {
			return nil
		}
		dir := b.WebClientSource
		if err := b.Command(dir, b.Yarn, "install").Run(); err != nil {
			return err
		}
		if err := b.Command(dir, b.Yarn, "build").Run(); err != nil {
			return err
		}
		return nil
	})
}

// BuildGoBinary builds the Go binary at path and returns the path to the
// binary. Builds are cached by path and env, so each build only happens once
// per process execution.
func (b *Build) BuildGoBinary(path string, env map[string]string) (string, error) {
	return b.BuildGoBinaryWithTags(path, env, nil)
}

// BuildGoBinaryWithTags builds the Go binary at path and returns the
// path to the binary. Builds are cached by path, env and tags, so
// each build only happens once per process execution.
//
// The passed in tags override gocross's automatic selection of build
// tags, so you will have to figure out and specify all the tags
// relevant to your build.
func (b *Build) BuildGoBinaryWithTags(path string, env map[string]string, tags []string) (string, error) {
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

	buildKey := []any{"go-build", path, env, tags}
	return b.goBuilds.Do(buildKey, func() (string, error) {
		b.goBuildLimit <- struct{}{}
		defer func() { <-b.goBuildLimit }()

		var envStrs []string
		for k, v := range env {
			envStrs = append(envStrs, k+"="+v)
		}
		sort.Strings(envStrs)
		buildDir := b.TmpDir()
		outPath := buildDir
		if env["GOOS"] == "windowsdll" {
			// DLL builds fail unless we use a fully-qualified path to the output binary.
			outPath = filepath.Join(buildDir, filepath.Base(path)+".dll")
		}
		args := []string{"build", "-v", "-o", outPath}
		if len(tags) > 0 {
			tagsStr := strings.Join(tags, ",")
			log.Printf("Building %s (with env %s, tags %s)", path, strings.Join(envStrs, " "), tagsStr)
			args = append(args, "-tags="+tagsStr)
		} else {
			log.Printf("Building %s (with env %s)", path, strings.Join(envStrs, " "))
		}
		args = append(args, path)
		cmd := b.Command(b.Repo, b.Go, args...)
		for k, v := range env {
			cmd.Cmd.Env = append(cmd.Cmd.Env, k+"="+v)
		}
		if err := cmd.Run(); err != nil {
			return "", err
		}
		out := filepath.Join(buildDir, filepath.Base(path))
		if env["GOOS"] == "windows" || env["GOOS"] == "windowsgui" {
			out += ".exe"
		} else if env["GOOS"] == "windowsdll" {
			out += ".dll"
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

// findTool returns the path to the specified named tool.
// It first looks in the "tool" directory in the provided path,
// then in the $PATH environment variable.
func findTool(path, name string) (string, error) {
	tool := filepath.Join(path, "tool", name)
	if _, err := os.Stat(tool); err == nil {
		return tool, nil
	}
	tool, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return tool, nil
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
