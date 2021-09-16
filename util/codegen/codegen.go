// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package codegen contains shared utilities for generating code.
package codegen

import (
	"fmt"
	"go/format"
	"os"
)

// WriteFormatted writes code to path.
// It runs gofmt on it before writing;
// if gofmt fails, it writes code unchanged.
// Errors can include I/O errors and gofmt errors.
//
// The advantage of always writing code to path,
// even if gofmt fails, is that it makes debugging easier.
// The code can be long, but you need it in order to debug.
// It is nicer to work with it in a file than a terminal.
// It is also easier to interpret gofmt errors
// with an editor providing file and line numbers.
func WriteFormatted(code []byte, path string) error {
	out, fmterr := format.Source(code)
	if fmterr != nil {
		out = code
	}
	ioerr := os.WriteFile(path, out, 0644)
	// Prefer I/O errors. They're usually easier to fix,
	// and until they're fixed you can't do much else.
	if ioerr != nil {
		return ioerr
	}
	if fmterr != nil {
		return fmt.Errorf("%s:%v", path, fmterr)
	}
	return nil
}
