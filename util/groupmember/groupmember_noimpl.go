// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo && !linux && !darwin
// +build !cgo,!linux,!darwin

package groupmember

func isMemberOfGroup(group, name string) (bool, error) { return false, ErrNotImplemented }
