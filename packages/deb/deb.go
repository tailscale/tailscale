// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package deb extracts metadata from Debian packages.
package deb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Info is the Debian package metadata needed to integrate the package
// into a repository.
type Info struct {
	// Version is the version of the package, as reported by dpkg.
	Version string
	// Arch is the Debian CPU architecture the package is for.
	Arch string
	// Control is the entire contents of the package's control file,
	// with leading and trailing whitespace removed.
	Control []byte
	// MD5 is the MD5 hash of the package file.
	MD5 []byte
	// SHA1 is the SHA1 hash of the package file.
	SHA1 []byte
	// SHA256 is the SHA256 hash of the package file.
	SHA256 []byte
}

// ReadFile returns Debian package metadata from the .deb file at path.
func ReadFile(path string) (*Info, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return Read(f)
}

// Read returns Debian package metadata from the .deb file in r.
func Read(r io.Reader) (*Info, error) {
	b := bufio.NewReader(r)

	m5, s1, s256 := md5.New(), sha1.New(), sha256.New()
	summers := io.MultiWriter(m5, s1, s256)
	r = io.TeeReader(b, summers)

	t, err := findControlTar(r)
	if err != nil {
		return nil, fmt.Errorf("searching for control.tar.gz: %w", err)
	}

	control, err := findControlFile(t)
	if err != nil {
		return nil, fmt.Errorf("searching for control file in control.tar.gz: %w", err)
	}

	arch, version, err := findArchAndVersion(control)
	if err != nil {
		return nil, fmt.Errorf("extracting version and architecture from control file: %w", err)
	}

	// Exhaust the remainder of r, so that the summers see the entire file.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return nil, fmt.Errorf("hashing file: %w", err)
	}

	return &Info{
		Version: version,
		Arch:    arch,
		Control: control,
		MD5:     m5.Sum(nil),
		SHA1:    s1.Sum(nil),
		SHA256:  s256.Sum(nil),
	}, nil
}

// findControlTar reads r as an `ar` archive, finds a tarball named
// `control.tar.gz` within, and returns a reader for that file.
func findControlTar(r io.Reader) (tarReader io.Reader, err error) {
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, fmt.Errorf("reading ar magic: %w", err)
	}
	if string(magic[:]) != "!<arch>\n" {
		return nil, fmt.Errorf("not an ar file (bad magic %q)", magic)
	}

	for {
		var hdr [60]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, fmt.Errorf("reading file header: %w", err)
		}
		filename := strings.TrimSpace(string(hdr[:16]))
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("reading size of file %q: %w", filename, err)
		}
		if filename == "control.tar.gz" {
			return io.LimitReader(r, size), nil
		}

		// files in ar are padded out to 2 bytes.
		if size%2 == 1 {
			size++
		}
		if _, err := io.CopyN(io.Discard, r, size); err != nil {
			return nil, fmt.Errorf("seeking past file %q: %w", filename, err)
		}
	}
}

// findControlFile reads r as a tar.gz archive, finds a file named
// `control` within, and returns its contents.
func findControlFile(r io.Reader) (control []byte, err error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("decompressing control.tar.gz: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("EOF while looking for control file in control.tar.gz")
			}
			return nil, fmt.Errorf("reading tar header: %w", err)
		}

		if filepath.Clean(hdr.Name) != "control" {
			continue
		}

		// Found control file
		break
	}

	bs, err := io.ReadAll(tr)
	if err != nil {
		return nil, fmt.Errorf("reading control file: %w", err)
	}

	return bytes.TrimSpace(bs), nil
}

var (
	archKey    = []byte("Architecture:")
	versionKey = []byte("Version:")
)

// findArchAndVersion extracts the architecture and version strings
// from the given control file.
func findArchAndVersion(control []byte) (arch string, version string, err error) {
	b := bytes.NewBuffer(control)
	for {
		ln, err := b.ReadBytes('\n')
		if err != nil {
			return "", "", err
		}
		if bytes.HasPrefix(ln, archKey) {
			arch = string(bytes.TrimSpace(ln[len(archKey):]))
		} else if bytes.HasPrefix(ln, versionKey) {
			version = string(bytes.TrimSpace(ln[len(versionKey):]))
		}
		if arch != "" && version != "" {
			return arch, version, nil
		}
	}
}
