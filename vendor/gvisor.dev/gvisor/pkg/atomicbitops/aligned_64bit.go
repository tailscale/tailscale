// Copyright 2021 The gVisor Authors.
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

//go:build !arm && !mips && !mipsle && !386
// +build !arm,!mips,!mipsle,!386

package atomicbitops

import "sync/atomic"

// AlignedAtomicInt64 is an atomic int64 that is guaranteed to be 64-bit
// aligned, even on 32-bit systems. On most architectures, it's just a regular
// int64.
//
// See aligned_unsafe.go in this directory for justification.
//
// +stateify savable
type AlignedAtomicInt64 struct {
	value int64
}

// Load is analagous to atomic.LoadInt64.
func (aa *AlignedAtomicInt64) Load() int64 {
	return atomic.LoadInt64(&aa.value)
}

// Store is analagous to atomic.StoreInt64.
func (aa *AlignedAtomicInt64) Store(v int64) {
	atomic.StoreInt64(&aa.value, v)
}

// Add is analagous to atomic.AddInt64.
func (aa *AlignedAtomicInt64) Add(v int64) int64 {
	return atomic.AddInt64(&aa.value, v)
}

// AlignedAtomicUint64 is an atomic uint64 that is guaranteed to be 64-bit
// aligned, even on 32-bit systems. On most architectures, it's just a regular
// uint64.
//
// See aligned_unsafe.go in this directory for justification.
//
// +stateify savable
type AlignedAtomicUint64 struct {
	value uint64
}

// Load is analagous to atomic.LoadUint64.
func (aa *AlignedAtomicUint64) Load() uint64 {
	return atomic.LoadUint64(&aa.value)
}

// Store is analagous to atomic.StoreUint64.
func (aa *AlignedAtomicUint64) Store(v uint64) {
	atomic.StoreUint64(&aa.value, v)
}

// Add is analagous to atomic.AddUint64.
func (aa *AlignedAtomicUint64) Add(v uint64) uint64 {
	return atomic.AddUint64(&aa.value, v)
}
