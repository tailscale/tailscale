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

//go:build race && amd64
// +build race,amd64

#include "textflag.h"

// func RaceUncheckedAtomicCompareAndSwapUintptr(ptr *uintptr, old, new uintptr) bool
TEXT ·RaceUncheckedAtomicCompareAndSwapUintptr(SB),NOSPLIT,$0-25
	MOVQ ptr+0(FP), DI
	MOVQ old+8(FP), AX
	MOVQ new+16(FP), SI

	LOCK
	CMPXCHGQ SI, 0(DI)

	SETEQ AX
	MOVB AX, ret+24(FP)

	RET

