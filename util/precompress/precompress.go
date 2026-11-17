// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package precompress provides build-time support for precompressing static
// resources (using Zstandard), to avoid the cost of repeatedly compressing
// unchanging resources. Serving the resulting variants is handled by
// tailscale.com/tsweb/compserve.
package precompress

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/errgroup"
	"tailscale.com/tsweb/compserve"
)

// PrecompressDir compresses static assets in dirPath using Zstandard.
func PrecompressDir(dirPath string, options Options) error {
	var eg errgroup.Group
	err := fs.WalkDir(os.DirFS(dirPath), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !compressibleExtensions[filepath.Ext(p)] {
			return nil
		}
		p = path.Join(dirPath, p)
		if options.ProgressFn != nil {
			options.ProgressFn(p)
		}

		eg.Go(func() error {
			return Precompress(p, options)
		})
		return nil
	})
	if err != nil {
		return err
	}
	return eg.Wait()
}

type Options struct {
	// FastCompression controls whether compression should be optimized for
	// speed rather than size.
	FastCompression bool
	// ProgressFn, if non-nil, is invoked when a file in the directory is about
	// to be compressed.
	ProgressFn func(path string)
}

var compressibleExtensions = map[string]bool{
	".js":  true,
	".css": true,
}

func Precompress(path string, options Options) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}

	zstdLevel := zstd.WithEncoderLevel(zstd.SpeedBestCompression)
	if options.FastCompression {
		zstdLevel = zstd.WithEncoderLevel(zstd.SpeedFastest)
	}
	return writeCompressed(contents, func(w io.Writer) (io.WriteCloser, error) {
		// Per RFC 8878, encoders should avoid window sizes larger than 8MB, which is the max that Chrome accepts.
		return zstd.NewWriter(w, zstdLevel, zstd.WithWindowSize(8<<20))
	}, path+compserve.Zstd.Ext, fi.Mode())
}

func writeCompressed(contents []byte, compressedWriterCreator func(io.Writer) (io.WriteCloser, error), outputPath string, outputMode fs.FileMode) error {
	var buf bytes.Buffer
	compressedWriter, err := compressedWriterCreator(&buf)
	if err != nil {
		return err
	}
	if _, err := compressedWriter.Write(contents); err != nil {
		return err
	}
	if err := compressedWriter.Close(); err != nil {
		return err
	}
	return os.WriteFile(outputPath, buf.Bytes(), outputMode)
}
