// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
	"io"
	"math/rand"
	"os"
	"testing"
	"testing/iotest"

	"tailscale.com/util/must"
)

func TestResume(t *testing.T) {
	oldBlockSize := blockSize
	defer func() { blockSize = oldBlockSize }()
	blockSize = 256

	m := managerOptions{Logf: t.Logf, Dir: t.TempDir()}.New()
	defer m.Shutdown()

	rn := rand.New(rand.NewSource(0))
	want := make([]byte, 12345)
	must.Get(io.ReadFull(rn, want))

	t.Run("resume-noexist", func(t *testing.T) {
		r := io.Reader(bytes.NewReader(want))

		next, close, err := m.HashPartialFile("", "foo")
		must.Do(err)
		defer close()
		offset, r, err := resumeReader(r, next)
		must.Do(err)
		must.Do(close()) // Windows wants the file handle to be closed to rename it.

		must.Get(m.PutFile("", "foo", r, offset, -1))
		got := must.Get(os.ReadFile(must.Get(joinDir(m.opts.Dir, "foo"))))
		if !bytes.Equal(got, want) {
			t.Errorf("content mismatches")
		}
	})

	t.Run("resume-retry", func(t *testing.T) {
		rn := rand.New(rand.NewSource(0))
		for i := 0; true; i++ {
			r := io.Reader(bytes.NewReader(want))

			next, close, err := m.HashPartialFile("", "bar")
			must.Do(err)
			defer close()
			offset, r, err := resumeReader(r, next)
			must.Do(err)
			must.Do(close()) // Windows wants the file handle to be closed to rename it.

			numWant := rn.Int63n(min(int64(len(want))-offset, 1000) + 1)
			if offset < int64(len(want)) {
				r = io.MultiReader(io.LimitReader(r, numWant), iotest.ErrReader(io.ErrClosedPipe))
			}
			if _, err := m.PutFile("", "bar", r, offset, -1); err == nil {
				break
			}
			if i > 1000 {
				t.Fatalf("too many iterations to complete the test")
			}
		}
		got := must.Get(os.ReadFile(must.Get(joinDir(m.opts.Dir, "bar"))))
		if !bytes.Equal(got, want) {
			t.Errorf("content mismatches")
		}
	})
}
