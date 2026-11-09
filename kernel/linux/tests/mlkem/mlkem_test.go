// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package mlkem checks tswg's ML-KEM-768 (src/mlkem.c) against Go's
// crypto/mlkem, which Tailscale's wireguard-go uses for its hybrid
// handshakes. It builds src/mlkem.c for userspace (with the stand-in
// kernel headers in testdata/shim) into a driver it talks to over a pipe.
//
// It needs a C compiler, and skips without one.
package mlkem

import (
	"bufio"
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// driver is a running driver.c.
type driver struct {
	t   *testing.T
	in  io.Writer
	out *bufio.Scanner
}

func startDriver(t *testing.T) *driver {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("no C compiler")
	}
	bin := filepath.Join(t.TempDir(), "driver")
	cc := exec.Command("cc", "-O2", "-std=gnu11", "-Wall", "-Wno-unused-function",
		"-Itestdata/shim", "-o", bin, "testdata/driver.c")
	if out, err := cc.CombinedOutput(); err != nil {
		t.Fatalf("building driver: %v\n%s", err, out)
	}
	cmd := exec.Command(bin)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		in.Close()
		cmd.Wait()
	})
	sc := bufio.NewScanner(out)
	sc.Buffer(nil, 1<<20)
	return &driver{t: t, in: in, out: sc}
}

// call runs a driver command, returning its results, or nil for "err".
func (d *driver) call(cmd string, args ...[]byte) [][]byte {
	d.t.Helper()
	line := cmd
	for _, a := range args {
		line += " " + hex.EncodeToString(a)
	}
	if _, err := fmt.Fprintln(d.in, line); err != nil {
		d.t.Fatal(err)
	}
	if !d.out.Scan() {
		d.t.Fatalf("driver: %v", d.out.Err())
	}
	if d.out.Text() == "err" {
		return nil
	}
	var res [][]byte
	for _, f := range strings.Fields(d.out.Text()) {
		b, err := hex.DecodeString(f)
		if err != nil {
			d.t.Fatal(err)
		}
		res = append(res, b)
	}
	return res
}

const iterations = 200

func TestMLKEM768(t *testing.T) {
	d := startDriver(t)
	for i := range iterations {
		seed := make([]byte, mlkem.SeedSize)
		rand.Read(seed)
		goDK, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			t.Fatal(err)
		}
		goEK := goDK.EncapsulationKey()

		// Key generation from the same seed gives the same public key.
		r := d.call("keygen", seed)
		if r == nil {
			t.Fatal("keygen failed")
		}
		ek, dk := r[0], r[1]
		if !bytes.Equal(ek, goEK.Bytes()) {
			t.Fatalf("%d: encapsulation key differs from Go's", i)
		}

		// Go encapsulates, we decapsulate.
		goSS, goCT := goEK.Encapsulate()
		r = d.call("decaps", dk, goCT)
		if r == nil || !bytes.Equal(r[0], goSS) {
			t.Fatalf("%d: decapsulating Go's ciphertext: got %x, want %x", i, r, goSS)
		}

		// We encapsulate, Go decapsulates.
		r = d.call("encaps", ek)
		if r == nil {
			t.Fatalf("%d: encaps failed", i)
		}
		ct, ss := r[0], r[1]
		want, err := goDK.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ss, want) {
			t.Fatalf("%d: Go decapsulates our ciphertext to %x, we said %x", i, want, ss)
		}

		// A corrupted ciphertext is implicitly rejected, the same way.
		bad := bytes.Clone(goCT)
		bad[i%len(bad)] ^= 1 << (i % 8)
		want, err = goDK.Decapsulate(bad)
		if err != nil {
			t.Fatal(err)
		}
		r = d.call("decaps", dk, bad)
		if r == nil || !bytes.Equal(r[0], want) {
			t.Fatalf("%d: implicit rejection: got %x, want %x", i, r, want)
		}
		if bytes.Equal(want, goSS) {
			t.Fatalf("%d: corrupted ciphertext gave the real shared secret", i)
		}
	}
}

// TestInvalidEncapsulationKey checks that encapsulation rejects keys whose
// coefficients aren't reduced mod q, as Go does.
func TestInvalidEncapsulationKey(t *testing.T) {
	d := startDriver(t)
	seed := make([]byte, mlkem.SeedSize)
	rand.Read(seed)
	r := d.call("keygen", seed)
	if r == nil {
		t.Fatal("keygen failed")
	}
	for _, off := range []int{0, 384, 1149} {
		ek := bytes.Clone(r[0])
		// Set a 12-bit coefficient starting at byte off (even
		// coefficients start on byte boundaries) to 4095.
		ek[off] = 0xff
		ek[off+1] |= 0x0f
		if _, err := mlkem.NewEncapsulationKey768(ek); err == nil {
			t.Fatalf("Go accepted the key corrupted at %d", off)
		}
		if d.call("encaps", ek) != nil {
			t.Errorf("encaps accepted the key corrupted at %d", off)
		}
	}
}
