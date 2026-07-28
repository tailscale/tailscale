// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package nardump writes a NAR (Nix Archive) representation of an
// fs.FS to an io.Writer, or summarizes it as a Subresource Integrity
// hash, as used by Nix flake.nix vendor and toolchain hashes.
//
// For the format, see:
// https://gist.github.com/jbeda/5c79d2b1434f0018d693
package nardump

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
)

// WriteNAR writes a NAR-encoded representation of fsys, rooted at
// the FS root, to w.
//
// The encoder issues many small writes; if w is not already a
// *bufio.Writer, WriteNAR wraps it in one and flushes on return so
// the caller doesn't have to.
//
// fsys must implement fs.ReadLinkFS to encode any symlinks it
// contains; os.DirFS satisfies this on Go 1.25+.
func WriteNAR(w io.Writer, fsys fs.FS) (err error) {
	defer func() {
		if e := recover(); e != nil {
			if we, ok := e.(writeNARError); ok {
				err = we.err
				return
			}
			panic(e)
		}
	}()
	bw, ok := w.(*bufio.Writer)
	if !ok {
		bw = bufio.NewWriter(w)
		defer func() {
			if flushErr := bw.Flush(); err == nil {
				err = flushErr
			}
		}()
	}
	nw := &narWriter{w: bw, fs: fsys}
	nw.str("nix-archive-1")
	return nw.writeDir(".")
}

// SRI returns the Subresource Integrity hash of the NAR encoding of
// fsys, in the form "sha256-<base64>". This is the format Nix
// expects for vendorHash and similar fields.
func SRI(fsys fs.FS) (string, error) {
	h := sha256.New()
	if err := WriteNAR(h, fsys); err != nil {
		return "", err
	}
	return "sha256-" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// writeNARError is a sentinel panic type that's recovered by
// WriteNAR and converted into the wrapped error.
type writeNARError struct{ err error }

// narWriter writes NAR files.
type narWriter struct {
	w  io.Writer
	fs fs.FS
}

func (nw *narWriter) writeDir(dirPath string) error {
	ents, err := fs.ReadDir(nw.fs, dirPath)
	if err != nil {
		return err
	}
	sort.Slice(ents, func(i, j int) bool {
		return ents[i].Name() < ents[j].Name()
	})
	nw.str("(")
	nw.str("type")
	nw.str("directory")
	for _, ent := range ents {
		nw.str("entry")
		nw.str("(")
		nw.str("name")
		nw.str(ent.Name())
		nw.str("node")
		mode := ent.Type()
		sub := path.Join(dirPath, ent.Name())
		var err error
		switch {
		case mode.IsDir():
			err = nw.writeDir(sub)
		case mode.IsRegular():
			err = nw.writeRegular(sub)
		case mode&fs.ModeSymlink != 0:
			err = nw.writeSymlink(sub)
		default:
			return fmt.Errorf("unsupported file type %v at %q", sub, mode)
		}
		if err != nil {
			return err
		}
		nw.str(")")
	}
	nw.str(")")
	return nil
}

func (nw *narWriter) writeRegular(p string) error {
	nw.str("(")
	nw.str("type")
	nw.str("regular")
	fi, err := fs.Stat(nw.fs, p)
	if err != nil {
		return err
	}
	if fi.Mode()&0111 != 0 {
		nw.str("executable")
		nw.str("")
	}
	contents, err := fs.ReadFile(nw.fs, p)
	if err != nil {
		return err
	}
	nw.str("contents")
	if err := writeBytes(nw.w, contents); err != nil {
		return err
	}
	nw.str(")")
	return nil
}

func (nw *narWriter) writeSymlink(p string) error {
	nw.str("(")
	nw.str("type")
	nw.str("symlink")
	nw.str("target")
	link, err := fs.ReadLink(nw.fs, p)
	if err != nil {
		return err
	}
	nw.str(link)
	nw.str(")")
	return nil
}

func (nw *narWriter) str(s string) {
	if err := writeString(nw.w, s); err != nil {
		panic(writeNARError{err})
	}
}

func writeString(w io.Writer, s string) error {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(len(s)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, s); err != nil {
		return err
	}
	return writePad(w, len(s))
}

func writeBytes(w io.Writer, b []byte) error {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(len(b)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	return writePad(w, len(b))
}

func writePad(w io.Writer, n int) error {
	pad := n % 8
	if pad == 0 {
		return nil
	}
	var zeroes [8]byte
	_, err := w.Write(zeroes[:8-pad])
	return err
}
