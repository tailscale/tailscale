// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// nardump is like nix-store --dump, but in Go, writing a NAR
// file (tar-like, but focused on being reproducible) to stdout
// or to a hash with the --sri flag.
//
// It lets us calculate a Nix sha256 without the person running
// git-pull-oss.sh having Nix available.
package main

// For the format, see:
// See https://gist.github.com/jbeda/5c79d2b1434f0018d693

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"sort"
)

var sri = flag.Bool("sri", false, "print SRI")

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("usage: nardump <dir>")
	}
	arg := flag.Arg(0)
	if err := os.Chdir(arg); err != nil {
		log.Fatal(err)
	}
	if *sri {
		hash := sha256.New()
		if err := writeNAR(hash, os.DirFS(".")); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("sha256-%s\n", base64.StdEncoding.EncodeToString(hash.Sum(nil)))
		return
	}
	bw := bufio.NewWriter(os.Stdout)
	if err := writeNAR(bw, os.DirFS(".")); err != nil {
		log.Fatal(err)
	}
	bw.Flush()
}

// writeNARError is a sentinel panic type that's recovered by writeNAR
// and converted into the wrapped error.
type writeNARError struct{ err error }

// narWriter writes NAR files.
type narWriter struct {
	w  io.Writer
	fs fs.FS
}

// writeNAR writes a NAR file to w from the root of fs.
func writeNAR(w io.Writer, fs fs.FS) (err error) {
	defer func() {
		if e := recover(); e != nil {
			if we, ok := e.(writeNARError); ok {
				err = we.err
				return
			}
			panic(e)
		}
	}()
	nw := &narWriter{w: w, fs: fs}
	nw.str("nix-archive-1")
	return nw.writeDir(".")
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
		case mode&os.ModeSymlink != 0:
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

func (nw *narWriter) writeRegular(path string) error {
	nw.str("(")
	nw.str("type")
	nw.str("regular")
	fi, err := fs.Stat(nw.fs, path)
	if err != nil {
		return err
	}
	if fi.Mode()&0111 != 0 {
		nw.str("executable")
		nw.str("")
	}
	contents, err := fs.ReadFile(nw.fs, path)
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

func (nw *narWriter) writeSymlink(path string) error {
	nw.str("(")
	nw.str("type")
	nw.str("symlink")
	nw.str("target")
	// broken symlinks are valid in a nar
	// given we do os.chdir(dir) and os.dirfs(".") above
	// readlink now resolves relative links even if they are broken
	link, err := os.Readlink(path)
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
