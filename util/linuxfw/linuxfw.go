// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package linuxfw returns the kind of firewall being used by the kernel.
package linuxfw

import "errors"

// ErrUnsupported is the error returned from all functions on non-Linux
// platforms.
var ErrUnsupported = errors.New("unsupported")
