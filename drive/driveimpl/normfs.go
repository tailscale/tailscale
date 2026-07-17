// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package driveimpl

import (
	"context"
	"errors"
	iofs "io/fs"
	"os"
	"path"
	"strings"

	"github.com/tailscale/xnet/webdav"
	"golang.org/x/text/unicode/norm"
)

// normalizingFS extends a webdav.FileSystem to resolve paths in a Unicode
// normalization-insensitive way. Different clients encode non-ASCII filenames
// differently: for example, macOS WebDAV clients request paths in NFD form,
// while files on disk are often named in NFC form. On normalization-sensitive
// filesystems like ext4, opening the NFD name of an NFC file fails. When an
// exact lookup fails, normalizingFS rescans the parent directory for an entry
// whose name is canonically equivalent to the requested one and uses that
// instead. See https://github.com/tailscale/tailscale/issues/15020.
type normalizingFS struct {
	webdav.FileSystem
}

func (fs *normalizingFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return fs.FileSystem.Mkdir(ctx, fs.resolve(ctx, name), perm)
}

func (fs *normalizingFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	return fs.FileSystem.OpenFile(ctx, fs.resolve(ctx, name), flag, perm)
}

func (fs *normalizingFS) RemoveAll(ctx context.Context, name string) error {
	return fs.FileSystem.RemoveAll(ctx, fs.resolve(ctx, name))
}

func (fs *normalizingFS) Rename(ctx context.Context, oldName, newName string) error {
	return fs.FileSystem.Rename(ctx, fs.resolve(ctx, oldName), fs.resolve(ctx, newName))
}

func (fs *normalizingFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	return fs.FileSystem.Stat(ctx, fs.resolve(ctx, name))
}

// resolve maps name to the path of an existing file whose name is canonically
// equivalent to name under Unicode NFC normalization. Exact matches always
// win. Path components with no existing equivalent are left as given, so that
// newly created files keep the exact name that the client requested.
func (fs *normalizingFS) resolve(ctx context.Context, name string) string {
	if isASCII(name) {
		// ASCII strings are canonically equivalent only to themselves.
		return name
	}
	if _, err := fs.FileSystem.Stat(ctx, name); err == nil || !errors.Is(err, iofs.ErrNotExist) {
		return name
	}
	resolved := "/"
	parts := strings.Split(strings.Trim(path.Clean("/"+name), "/"), "/")
	for i, part := range parts {
		candidate := path.Join(resolved, part)
		if isASCII(part) {
			resolved = candidate
			continue
		}
		if _, err := fs.FileSystem.Stat(ctx, candidate); err == nil {
			resolved = candidate
			continue
		}
		match, ok := fs.findEquivalent(ctx, resolved, part)
		if !ok {
			// No equivalent entry exists. Keep the remaining components
			// as given; deeper lookups would fail anyway.
			return path.Join(append([]string{resolved}, parts[i:]...)...)
		}
		resolved = path.Join(resolved, match)
	}
	return resolved
}

// findEquivalent scans the directory at dir for an entry whose name is
// canonically equivalent to name, returning the on-disk name if found.
func (fs *normalizingFS) findEquivalent(ctx context.Context, dir, name string) (string, bool) {
	d, err := fs.FileSystem.OpenFile(ctx, dir, os.O_RDONLY, 0)
	if err != nil {
		return "", false
	}
	defer d.Close()
	fis, err := d.Readdir(0)
	if err != nil {
		return "", false
	}
	want := norm.NFC.String(name)
	for _, fi := range fis {
		if norm.NFC.String(fi.Name()) == want {
			return fi.Name(), true
		}
	}
	return "", false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
