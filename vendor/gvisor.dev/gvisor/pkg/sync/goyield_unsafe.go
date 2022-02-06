// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.14
// +build go1.14

// //go:linkname directives type-checked by checklinkname. Any other
// non-linkname assumptions outside the Go 1 compatibility guarantee should
// have an accompanied vet check or version guard build tag.

package sync

import (
	_ "unsafe" // for go:linkname
)

//go:linkname goyield runtime.goyield
func goyield()
