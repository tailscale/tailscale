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

	m := Manager{Logf: t.Logf, Dir: t.TempDir()}

	rn := rand.New(rand.NewSource(0))
	want := make([]byte, 12345)
	must.Get(io.ReadFull(rn, want))

	t.Run("resume-noop", func(t *testing.T) {
		r := io.Reader(bytes.NewReader(want))
		offset, r, err := ResumeReader(r, func(offset, length int64) (FileChecksums, error) {
			return m.HashPartialFile("", "foo", offset, length)
		})
		must.Do(err)
		must.Get(m.PutFile("", "foo", r, offset, -1))
		got := must.Get(os.ReadFile(must.Get(m.joinDir("foo"))))
		if !bytes.Equal(got, want) {
			t.Errorf("content mismatches")
		}
	})

	t.Run("resume-retry", func(t *testing.T) {
		rn := rand.New(rand.NewSource(0))
		for {
			r := io.Reader(bytes.NewReader(want))
			offset, r, err := ResumeReader(r, func(offset, length int64) (FileChecksums, error) {
				return m.HashPartialFile("", "foo", offset, length)
			})
			must.Do(err)
			numWant := rn.Int63n(min(int64(len(want))-offset, 1000) + 1)
			if offset < int64(len(want)) {
				r = io.MultiReader(io.LimitReader(r, numWant), iotest.ErrReader(io.ErrClosedPipe))
			}
			if _, err := m.PutFile("", "foo", r, offset, -1); err == nil {
				break
			}
		}
		got := must.Get(os.ReadFile(must.Get(m.joinDir("foo"))))
		if !bytes.Equal(got, want) {
			t.Errorf("content mismatches")
		}
	})

}
