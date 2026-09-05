// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(freebsd && arm64) && !ts_omit_cpucaps

package cpucaps

// hostCapsArch returns capabilities not detectable via x/sys/cpu.
// On most platforms x/sys/cpu is complete and this returns 0; see
// caps_freebsd_arm64.go for the exception.
func hostCapsArch() Caps { return 0 }
