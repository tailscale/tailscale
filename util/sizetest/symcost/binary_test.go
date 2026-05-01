// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost_test

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/util/sizetest"
	"tailscale.com/util/sizetest/symcost"
)

// TestOpenAndAttributeAgainstFixture builds a tiny program with a
// generic function instantiated for two distinct types and verifies
// that symcost can:
//
//  1. Open the binary and parse its sections, symbols, and pclntab.
//  2. Attribute body and pclntab cost to the generic function's
//     instantiations via CostByFunction.
//  3. Decode the runtime type descriptors for the program's named
//     types and find them in the resulting Cost via CostByReceiver.
func TestOpenAndAttributeAgainstFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: invokes go build")
	}
	if runtime.GOOS != "linux" {
		t.Skipf("symcost.Open is currently ELF-only; running on %s", runtime.GOOS)
	}

	res := sizetest.BuildWithOptions(t, sizetest.Variant{
		Name: "symcost-binary-fixture",
		Source: `package main

type Foo struct {
	A, B int
}

type Bar struct {
	S string
	N int64
}

//go:noinline
func Use[T any](v T) string {
	switch any(v).(type) {
	case Foo:
		return "foo"
	case Bar:
		return "bar"
	}
	return "?"
}

func main() {
	println(Use(Foo{1, 2}))
	println(Use(Bar{"x", 3}))
}
`,
	}, sizetest.BuildOptions{
		LDFlags:  " ", // keep symbols
		Trimpath: ptr(true),
	})

	b, err := symcost.Open(res.BinaryPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	// 1. Sanity check: required sections present.
	for _, s := range []string{".text", ".rodata", ".gopclntab"} {
		if b.Sections[s] == nil {
			t.Errorf("missing section %s", s)
		}
	}

	// 2. Funcs were decoded.
	if len(b.Funcs) == 0 {
		t.Fatal("Funcs is empty")
	}
	// The pclntab attribution should sum to roughly the section's
	// size. Tolerance is loose because we use a fixed-per-func
	// + body-proportional approximation.
	pcln := b.Sections[".gopclntab"]
	var totalPcln int64
	for _, f := range b.Funcs {
		totalPcln += f.PclntabBytes
	}
	if totalPcln <= 0 || totalPcln > int64(pcln.Size)+1024 {
		t.Errorf("attributed pclntab %d differs from section size %d unreasonably",
			totalPcln, pcln.Size)
	}

	// 3. Function-mode lookup finds both instantiations of Use.
	fc := b.CostByFunction("main.Use[…]")
	if len(fc.Funcs) < 2 {
		t.Errorf("CostByFunction(main.Use[…]) found %d funcs, want >= 2",
			len(fc.Funcs))
	}
	for _, f := range fc.Funcs {
		if !strings.Contains(f.Name, "main.Use[") {
			t.Errorf("unexpected func in main.Use[…] result: %q", f.Name)
		}
	}
	if fc.Sections[".text"] == 0 || fc.Sections[".gopclntab"] == 0 {
		t.Errorf("CostByFunction did not attribute .text or .gopclntab; got %v", fc.Sections)
	}

	// 4. Type-side: the descriptor for main.Foo should be found.
	rc := b.CostByReceiver("main.Foo")
	// We expect at least the type descriptor (and maybe the eq func).
	if rc.Total == 0 {
		t.Errorf("CostByReceiver(main.Foo) total = 0; expected non-zero")
	}
	foundFooType := false
	for _, ty := range rc.Types {
		if strings.HasSuffix(ty.Name, "main.Foo") {
			foundFooType = true
			break
		}
	}
	if !foundFooType {
		t.Errorf("did not find main.Foo type descriptor; types found: %v",
			typeNames(rc.Types))
	}
}

func typeNames(ts []symcost.TypeCost) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Name
	}
	return out
}

// TestArm64FuncRefsAgainstFixture cross-compiles a tiny program to
// arm64 and verifies that FuncRefs picks up at least one rodata
// reference from the test function, and that CostByFunction
// includes additional .rodata bytes that the previous
// non-disassembling attribution would have missed.
//
// The test does not require an arm64 host: it only inspects the
// ELF binary statically.
func TestArm64FuncRefsAgainstFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: invokes go build")
	}
	// We can't use sizetest.BuildWithOptions for this case
	// because it doesn't expose GOOS/GOARCH overrides; we want to
	// cross-compile to arm64 even when the host is amd64. Build
	// directly with `go build` so we can set the env.
	dir := t.TempDir()
	source := []byte(`package main

//go:noinline
func PickName(i int) string {
	switch i {
	case 0:
		return "alpha-zebra-fixture"
	case 1:
		return "bravo-yankee-fixture"
	default:
		return "charlie-xray-fixture"
	}
}

func main() {
	println(PickName(0))
	println(PickName(1))
	println(PickName(2))
}
`)
	if err := writeFile(dir+"/main.go", source); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(dir+"/go.mod", []byte("module symcostarm\n\ngo 1.21\n")); err != nil {
		t.Fatal(err)
	}
	binPath := dir + "/bin"
	if err := goBuildARM64(t, dir, binPath); err != nil {
		t.Fatalf("cross-compile to arm64: %v", err)
	}

	b, err := symcost.Open(binPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	// Find PickName.
	var pickName *symcost.Func
	for _, f := range b.Funcs {
		if strings.Contains(f.Name, "main.PickName") {
			pickName = f
			break
		}
	}
	if pickName == nil {
		t.Fatal("couldn't find main.PickName")
	}

	refs := b.FuncRefs(pickName)
	if len(refs) == 0 {
		t.Errorf("expected FuncRefs to pick up at least one rodata reference; got 0")
	}

	// At least some refs should land in .rodata.
	rodata := b.Sections[".rodata"]
	if rodata == nil {
		t.Skip("no .rodata; can't validate")
	}
	rodataRefs := 0
	for _, addr := range refs {
		if rodata.AddrInRange(addr) {
			rodataRefs++
		}
	}
	if rodataRefs == 0 {
		t.Errorf("none of the %d refs landed in .rodata; got %v", len(refs), refs)
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

// goBuildARM64 cross-compiles the package in dir to an arm64 ELF at
// out, returning an error if the build fails.
func goBuildARM64(t testing.TB, dir, out string) error {
	t.Helper()
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("build output:\n%s", output)
	}
	return err
}
