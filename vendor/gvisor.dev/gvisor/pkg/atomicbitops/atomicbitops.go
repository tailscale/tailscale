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

//go:build amd64 || arm64
// +build amd64 arm64

// Package atomicbitops provides extensions to the sync/atomic package.
//
// All read-modify-write operations implemented by this package have
// acquire-release memory ordering (like sync/atomic).
package atomicbitops

// AndUint32 atomically applies bitwise AND operation to *addr with val.
func AndUint32(addr *uint32, val uint32)

// OrUint32 atomically applies bitwise OR operation to *addr with val.
func OrUint32(addr *uint32, val uint32)

// XorUint32 atomically applies bitwise XOR operation to *addr with val.
func XorUint32(addr *uint32, val uint32)

// CompareAndSwapUint32 is like sync/atomic.CompareAndSwapUint32, but returns
// the value previously stored at addr.
func CompareAndSwapUint32(addr *uint32, old, new uint32) uint32

// AndUint64 atomically applies bitwise AND operation to *addr with val.
func AndUint64(addr *uint64, val uint64)

// OrUint64 atomically applies bitwise OR operation to *addr with val.
func OrUint64(addr *uint64, val uint64)

// XorUint64 atomically applies bitwise XOR operation to *addr with val.
func XorUint64(addr *uint64, val uint64)

// CompareAndSwapUint64 is like sync/atomic.CompareAndSwapUint64, but returns
// the value previously stored at addr.
func CompareAndSwapUint64(addr *uint64, old, new uint64) uint64
