// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import "errors"

// DefaultFileOps is the non‑Android FileOps implementation.
// It exists on Android too so the stub constructor can compile,
// but Android never uses the value.
type DefaultFileOps struct{ rootDir string }

var newDefaultFileOps = func(dir string) (FileOps, error) { return nil, errors.New("FileOps is not implemented") }
