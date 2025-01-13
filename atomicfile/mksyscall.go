// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package atomicfile

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go

//sys replaceFileW(replaced *uint16, replacement *uint16, backup *uint16, flags uint32, exclude unsafe.Pointer, reserved unsafe.Pointer) (err error) [int32(failretval)==0] = kernel32.ReplaceFileW
