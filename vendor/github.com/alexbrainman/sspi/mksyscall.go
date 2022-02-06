// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sspi

//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -systemdll=false -output=zsyscall_windows.go syscall.go
