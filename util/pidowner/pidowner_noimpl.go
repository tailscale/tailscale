// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !linux

package pidowner

func ownerOfPID(pid int) (userID string, err error) { return "", ErrNotImplemented }
