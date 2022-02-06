// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build race && arm64
// +build race,arm64

#include "textflag.h"

// func RaceUncheckedAtomicCompareAndSwapUintptr(ptr *uintptr, old, new uintptr) bool
TEXT ·RaceUncheckedAtomicCompareAndSwapUintptr(SB),NOSPLIT,$0-25
	MOVD ptr+0(FP), R0
	MOVD old+8(FP), R1
	MOVD new+16(FP), R1
again:
	LDAXR (R0), R3
	CMP R1, R3
	BNE ok
	STLXR R2, (R0), R3
	CBNZ R3, again
ok:
	CSET EQ, R0
	MOVB R0, ret+24(FP)
	RET

