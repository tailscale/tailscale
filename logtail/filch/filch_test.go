// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filch

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"unicode"
)

type filchTest struct {
	*Filch
}

func newFilchTest(t *testing.T, filePrefix string, opts Options) *filchTest {
	f, err := New(filePrefix, opts)
	if err != nil {
		t.Fatal(err)
	}
	return &filchTest{Filch: f}
}

func (f *filchTest) write(t *testing.T, s string) {
	t.Helper()
	if _, err := f.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
}

func (f *filchTest) read(t *testing.T, want string) {
	t.Helper()
	if b, err := f.TryReadLine(); err != nil {
		t.Fatalf("r.ReadLine() err=%v", err)
	} else if got := strings.TrimRightFunc(string(b), unicode.IsSpace); got != want {
		t.Errorf("r.ReadLine()=%q, want %q", got, want)
	}
}

func (f *filchTest) readEOF(t *testing.T) {
	t.Helper()
	if b, err := f.TryReadLine(); b != nil || err != nil {
		t.Fatalf("r.ReadLine()=%q err=%v, want nil slice", string(b), err)
	}
}

func (f *filchTest) close(t *testing.T) {
	t.Helper()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestQueue(t *testing.T) {
	filePrefix := t.TempDir()
	f := newFilchTest(t, filePrefix, Options{ReplaceStderr: false})

	f.readEOF(t)
	const line1 = "Hello, World!"
	const line2 = "This is a test."
	const line3 = "Of filch."
	f.write(t, line1)
	f.write(t, line2)
	f.read(t, line1)
	f.write(t, line3)
	f.read(t, line2)
	f.read(t, line3)
	f.readEOF(t)
	f.write(t, line1)
	f.read(t, line1)
	f.readEOF(t)
	f.close(t)
}

func TestRecover(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		filePrefix := t.TempDir()
		f := newFilchTest(t, filePrefix, Options{ReplaceStderr: false})
		f.write(t, "hello")
		f.read(t, "hello")
		f.readEOF(t)
		f.close(t)

		f = newFilchTest(t, filePrefix, Options{ReplaceStderr: false})
		f.readEOF(t)
		f.close(t)
	})

	t.Run("cur", func(t *testing.T) {
		filePrefix := t.TempDir()
		f := newFilchTest(t, filePrefix, Options{ReplaceStderr: false})
		f.write(t, "hello")
		f.close(t)

		f = newFilchTest(t, filePrefix, Options{ReplaceStderr: false})
		f.read(t, "hello")
		f.readEOF(t)
		f.close(t)
	})

	t.Run("alt", func(t *testing.T) {
		t.Skip("currently broken on linux, passes on macOS")
		/* --- FAIL: TestRecover/alt (0.00s)
		filch_test.go:128: r.ReadLine()="world", want "hello"
		filch_test.go:129: r.ReadLine()="hello", want "world"
		*/

		filePrefix := t.TempDir()
		f := newFilchTest(t, filePrefix, Options{ReplaceStderr: false})
		f.write(t, "hello")
		f.read(t, "hello")
		f.write(t, "world")
		f.close(t)

		f = newFilchTest(t, filePrefix, Options{ReplaceStderr: false})
		// TODO(crawshaw): The "hello" log is replayed in recovery.
		//                 We could reduce replays by risking some logs loss.
		//                 What should our policy here be?
		f.read(t, "hello")
		f.read(t, "world")
		f.readEOF(t)
		f.close(t)
	})
}

func TestFilchStderr(t *testing.T) {
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeR.Close()
	defer pipeW.Close()

	stderrFD = int(pipeW.Fd())
	defer func() {
		stderrFD = 2
	}()

	filePrefix := t.TempDir()
	f := newFilchTest(t, filePrefix, Options{ReplaceStderr: true})
	f.write(t, "hello")
	if _, err := fmt.Fprintf(pipeW, "filch\n"); err != nil {
		t.Fatal(err)
	}
	f.read(t, "hello")
	f.read(t, "filch")
	f.readEOF(t)
	f.close(t)

	pipeW.Close()
	b, err := ioutil.ReadAll(pipeR)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 0 {
		t.Errorf("unexpected write to fake stderr: %s", b)
	}
}
