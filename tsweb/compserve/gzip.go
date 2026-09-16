// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package compserve

import (
	"compress/gzip"
	"io"
	"io/fs"
)

// Gzip serves gzip-precompressed variants ("*.gz"). It exists for
// transitional compatibility with file systems built before zstd-only
// asset generation, such as web-client-prebuilt modules published before
// cmd/build-webclient stopped writing gzip; file systems built since
// contain no .gz variants and never select it.
var Gzip = Encoding{
	Token:      "gzip",
	Ext:        ".gz",
	Decompress: decompressGzip,
}

// decompressGzip wraps f in a streaming gzip decompressor, taking
// ownership of f.
func decompressGzip(f fs.File) (io.ReadCloser, error) {
	zr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &gzipFile{f: f, Reader: zr}, nil
}

// gzipFile is a gzip.Reader reading from f; Close closes both.
type gzipFile struct {
	f fs.File
	*gzip.Reader
}

func (g *gzipFile) Close() error {
	g.Reader.Close()
	return g.f.Close()
}
