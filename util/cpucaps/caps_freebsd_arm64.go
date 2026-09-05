// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build freebsd && arm64 && !ts_omit_cpucaps

package cpucaps

// getisar0 returns the ID_AA64ISAR0_EL1 instruction set attribute
// register. The register is EL1-privileged, but the FreeBSD kernel
// emulates EL0 MRS reads of the ID_AA64* registers; Go's
// runtime/internal/cpu relies on the same emulation on this
// platform, so any running Go binary proves it is available.
func getisar0() uint64

// hostCapsArch supplements x/sys/cpu, which has no arm64 feature
// detection on FreeBSD (it reports only the baseline FP/ASIMD
// features there).
func hostCapsArch() Caps {
	return capsFromISAR0(getisar0())
}
