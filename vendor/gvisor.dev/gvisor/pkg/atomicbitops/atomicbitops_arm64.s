// Copyright 2019 The gVisor Authors.
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

// +build arm64

#include "textflag.h"

TEXT ·AndUint32(SB),NOSPLIT,$0-12
  MOVD    ptr+0(FP), R0
  MOVW    val+8(FP), R1
again:
  LDAXRW  (R0), R2
  ANDW    R1, R2
  STLXRW  R2, (R0), R3
  CBNZ    R3, again
  RET

TEXT ·OrUint32(SB),NOSPLIT,$0-12
  MOVD    ptr+0(FP), R0
  MOVW    val+8(FP), R1
again:
  LDAXRW  (R0), R2
  ORRW    R1, R2
  STLXRW  R2, (R0), R3
  CBNZ    R3, again
  RET

TEXT ·XorUint32(SB),NOSPLIT,$0-12
  MOVD    ptr+0(FP), R0
  MOVW    val+8(FP), R1
again:
  LDAXRW  (R0), R2
  EORW    R1, R2
  STLXRW  R2, (R0), R3
  CBNZ    R3, again
  RET

TEXT ·CompareAndSwapUint32(SB),NOSPLIT,$0-20
  MOVD addr+0(FP), R0
  MOVW old+8(FP), R1
  MOVW new+12(FP), R2
again:
  LDAXRW (R0), R3
  CMPW R1, R3
  BNE done
  STLXRW R2, (R0), R4
  CBNZ R4, again
done:
  MOVW R3, prev+16(FP)
  RET

TEXT ·AndUint64(SB),NOSPLIT,$0-16
  MOVD    ptr+0(FP), R0
  MOVD    val+8(FP), R1
again:
  LDAXR   (R0), R2
  AND     R1, R2
  STLXR   R2, (R0), R3
  CBNZ    R3, again
  RET

TEXT ·OrUint64(SB),NOSPLIT,$0-16
  MOVD    ptr+0(FP), R0
  MOVD    val+8(FP), R1
again:
  LDAXR   (R0), R2
  ORR     R1, R2
  STLXR   R2, (R0), R3
  CBNZ    R3, again
  RET

TEXT ·XorUint64(SB),NOSPLIT,$0-16
  MOVD    ptr+0(FP), R0
  MOVD    val+8(FP), R1
again:
  LDAXR   (R0), R2
  EOR     R1, R2
  STLXR   R2, (R0), R3
  CBNZ    R3, again
  RET

TEXT ·CompareAndSwapUint64(SB),NOSPLIT,$0-32
  MOVD addr+0(FP), R0
  MOVD old+8(FP), R1
  MOVD new+16(FP), R2
again:
  LDAXR (R0), R3
  CMP R1, R3
  BNE done
  STLXR R2, (R0), R4
  CBNZ R4, again
done:
  MOVD R3, prev+24(FP)
  RET
