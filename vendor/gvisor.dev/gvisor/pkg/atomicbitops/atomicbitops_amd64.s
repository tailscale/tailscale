// Copyright 2018 The gVisor Authors.
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

// +build amd64

#include "textflag.h"

TEXT ·AndUint32(SB),NOSPLIT,$0-12
  MOVQ  addr+0(FP), BX
  MOVL  val+8(FP), AX
  LOCK
  ANDL   AX, 0(BX)
  RET

TEXT ·OrUint32(SB),NOSPLIT,$0-12
  MOVQ  addr+0(FP), BX
  MOVL  val+8(FP), AX
  LOCK
  ORL   AX, 0(BX)
  RET

TEXT ·XorUint32(SB),NOSPLIT,$0-12
  MOVQ  addr+0(FP), BX
  MOVL  val+8(FP), AX
  LOCK
  XORL   AX, 0(BX)
  RET

TEXT ·CompareAndSwapUint32(SB),NOSPLIT,$0-20
  MOVQ  addr+0(FP), DI
  MOVL  old+8(FP), AX
  MOVL  new+12(FP), DX
  LOCK
  CMPXCHGL DX, 0(DI)
  MOVL  AX, ret+16(FP)
  RET

TEXT ·AndUint64(SB),NOSPLIT,$0-16
  MOVQ  addr+0(FP), BX
  MOVQ  val+8(FP), AX
  LOCK
  ANDQ   AX, 0(BX)
  RET

TEXT ·OrUint64(SB),NOSPLIT,$0-16
  MOVQ  addr+0(FP), BX
  MOVQ  val+8(FP), AX
  LOCK
  ORQ   AX, 0(BX)
  RET

TEXT ·XorUint64(SB),NOSPLIT,$0-16
  MOVQ  addr+0(FP), BX
  MOVQ  val+8(FP), AX
  LOCK
  XORQ   AX, 0(BX)
  RET

TEXT ·CompareAndSwapUint64(SB),NOSPLIT,$0-32
  MOVQ  addr+0(FP), DI
  MOVQ  old+8(FP), AX
  MOVQ  new+16(FP), DX
  LOCK
  CMPXCHGQ DX, 0(DI)
  MOVQ  AX, ret+24(FP)
  RET
