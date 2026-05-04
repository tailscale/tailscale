// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package sizetest is a reusable primitive for measuring how much a code
// change contributes to compiled binary size.
//
// The typical pattern is:
//
//   - Define two [Variant]s: a baseline and a treatment that differs only
//     in the dimension you want to measure (e.g. one extra eventbus flow,
//     one extra generic instantiation, one extra package import).
//   - Call [Diff] to build both variants and report the size delta.
//
// Caveats:
//
//   - Absolute byte counts are not portable across Go versions, GOOS, GOARCH,
//     or even minor toolchain configuration. Tests that bake in a specific
//     byte threshold should gate on a known build matrix or use the
//     [Result] values as informational output only.
//   - To reduce noise, builds are performed with -trimpath and ldflags
//     "-s -w" by default (no debug info, no symbol table). The remaining
//     size is dominated by code, rodata, and runtime type metadata, which
//     is what you usually want when measuring per-feature cost.
//   - Each Variant is built in its own temporary module that uses a
//     replace directive pointing at [ModuleRoot], so variant source can
//     freely import packages from this repository.
package sizetest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"tailscale.com/util/testenv"
)

// Variant is one program to be built and measured. Its Source must be
// a complete, compilable Go program for package main.
type Variant struct {
	// Name is a short human-readable identifier used in error messages
	// and test output. It must be a valid filesystem name component.
	Name string
	// Source is the complete Go source for a package main program. It
	// must contain `package main` and a `func main()`. Source may import
	// any package reachable from the module root (see [ModuleRoot]).
	Source string
	// ExtraFiles is an optional map of additional source files to write
	// alongside Source (filename -> contents). Used when a variant
	// needs supporting files in package main.
	ExtraFiles map[string]string
}

// Result is the outcome of building a single [Variant].
type Result struct {
	// Variant is the input that produced this result.
	Variant Variant
	// Bytes is the size of the compiled binary in bytes.
	Bytes int64
	// BinaryPath is the path to the compiled binary on disk. The file
	// lives in a t.TempDir() and is cleaned up when the test ends.
	BinaryPath string
}

// BuildOptions configures how variants are compiled.
type BuildOptions struct {
	// LDFlags is passed to `go build -ldflags`. If empty, "-s -w" is
	// used to strip the symbol table and DWARF info, which makes
	// measurements focus on code+rodata size and reduces cross-version
	// noise.
	//
	// Pass a non-empty value (e.g. " ") to override the default; pass
	// an explicit value to set custom flags.
	LDFlags string
	// Trimpath, if true, passes -trimpath to `go build`. Default true.
	// Disable only if you specifically want path strings in the binary.
	Trimpath *bool
	// GoFlags is appended verbatim to the `go build` command line
	// (after the standard flags). Useful for things like
	// "-tags=foo,bar".
	GoFlags []string
	// GOOS, if non-empty, sets GOOS for the build. Useful for
	// cross-compiling and measuring binary size on a non-host
	// platform. Note that the resulting binary cannot be run on
	// the host, but sizetest only stats it; that's fine.
	GOOS string
	// GOARCH, if non-empty, sets GOARCH for the build. Same caveats
	// as GOOS.
	GOARCH string
}

// DefaultBuildOptions are the build options used when none are supplied.
// They favor low-noise, reproducible measurements over realism.
var DefaultBuildOptions = BuildOptions{
	LDFlags:  "-s -w",
	Trimpath: ptr(true),
}

func ptr[T any](v T) *T { return &v }

// Build compiles v and returns its size. It uses [DefaultBuildOptions].
// See [BuildWithOptions] for control over build flags.
func Build(t testenv.TB, v Variant) Result {
	t.Helper()
	return BuildWithOptions(t, v, DefaultBuildOptions)
}

// BuildWithOptions compiles v with the supplied options and returns
// its size.
//
// Build artifacts (the temporary module and the resulting binary) live
// in t.TempDir() and are cleaned up when the test ends.
func BuildWithOptions(t testenv.TB, v Variant, opts BuildOptions) Result {
	t.Helper()

	if v.Name == "" {
		t.Fatal("sizetest: Variant.Name is required")
	}
	if !strings.Contains(v.Source, "package main") {
		t.Fatalf("sizetest: Variant %q Source must declare package main", v.Name)
	}

	root, err := ModuleRoot()
	if err != nil {
		t.Fatalf("sizetest: locating module root: %v", err)
	}

	dir := filepath.Join(t.TempDir(), sanitize(v.Name))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("sizetest: mkdir variant dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(v.Source), 0o644); err != nil {
		t.Fatalf("sizetest: writing main.go for %q: %v", v.Name, err)
	}
	for name, contents := range v.ExtraFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatalf("sizetest: writing extra file %q for %q: %v", name, v.Name, err)
		}
	}

	// Synthesize a tiny module that pins to the repo via a replace
	// directive. This keeps the variant compilable against the
	// in-tree version of any imported packages.
	goMod := fmt.Sprintf(`module sizetestvariant/%s

go %s

require tailscale.com v0.0.0
replace tailscale.com => %s
`, sanitize(v.Name), shortGoVersion(), filepath.ToSlash(root))
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("sizetest: writing go.mod: %v", err)
	}

	// Reuse the parent module's go.sum so we don't need network access
	// to resolve transitive dependencies. The replace directive above
	// covers tailscale.com itself; the rest is whatever it transitively
	// pulls in.
	if data, err := os.ReadFile(filepath.Join(root, "go.sum")); err == nil {
		if err := os.WriteFile(filepath.Join(dir, "go.sum"), data, 0o644); err != nil {
			t.Fatalf("sizetest: copying go.sum: %v", err)
		}
	}

	binPath := filepath.Join(dir, "out")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	args := []string{"build"}
	if opts.Trimpath == nil || *opts.Trimpath {
		args = append(args, "-trimpath")
	}
	if ld := opts.LDFlags; ld != "" {
		args = append(args, "-ldflags="+ld)
	}
	args = append(args, opts.GoFlags...)
	args = append(args, "-o", binPath, ".")

	cmd := exec.CommandContext(t.Context(), "go", args...)
	cmd.Dir = dir
	// Force module mode and disable network by default; the parent
	// module's go.sum + module cache should satisfy us.
	env := append(os.Environ(),
		"GOFLAGS=-mod=mod",
	)
	if opts.GOOS != "" {
		env = append(env, "GOOS="+opts.GOOS)
	}
	if opts.GOARCH != "" {
		env = append(env, "GOARCH="+opts.GOARCH)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sizetest: building variant %q with `go %s`:\n%s\nerror: %v",
			v.Name, strings.Join(args, " "), out, err)
	}

	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("sizetest: stat built binary for %q: %v", v.Name, err)
	}

	return Result{
		Variant:    v,
		Bytes:      info.Size(),
		BinaryPath: binPath,
	}
}

// Diff builds baseline and treatment and returns their results plus
// the byte delta (treatment - baseline). A positive delta means the
// treatment is larger.
func Diff(t testenv.TB, baseline, treatment Variant) (baselineRes, treatmentRes Result, delta int64) {
	t.Helper()
	return DiffWithOptions(t, baseline, treatment, DefaultBuildOptions)
}

// DiffWithOptions is like [Diff] but accepts custom build options.
func DiffWithOptions(t testenv.TB, baseline, treatment Variant, opts BuildOptions) (baselineRes, treatmentRes Result, delta int64) {
	t.Helper()
	baselineRes = BuildWithOptions(t, baseline, opts)
	treatmentRes = BuildWithOptions(t, treatment, opts)
	delta = treatmentRes.Bytes - baselineRes.Bytes
	return baselineRes, treatmentRes, delta
}

// ModuleRoot returns the absolute filesystem path to the root of the
// module containing the sizetest package itself (i.e. the tailscale.com
// module). It locates the root by walking up from the package's
// runtime-recorded source path until a go.mod is found.
func ModuleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod found above sizetest package")
		}
		dir = parent
	}
}

// sanitize maps an arbitrary name to something safe to use as a
// filesystem name component and Go module path element.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "variant"
	}
	return b.String()
}

// shortGoVersion returns the major.minor portion of runtime.Version()
// (e.g. "1.26") for use in a synthesized go.mod file.
func shortGoVersion() string {
	v := runtime.Version() // "go1.26.2"
	v = strings.TrimPrefix(v, "go")
	// Trim to major.minor.
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}
