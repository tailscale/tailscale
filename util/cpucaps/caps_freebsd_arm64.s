// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build freebsd && arm64 && gc && !ts_omit_cpucaps

#include "textflag.h"

// func getisar0() uint64
TEXT ·getisar0(SB), NOSPLIT, $0-8
	// get Instruction Set Attributes 0 into R0
	MRS	ID_AA64ISAR0_EL1, R0
	MOVD	R0, ret+0(FP)
	RET
