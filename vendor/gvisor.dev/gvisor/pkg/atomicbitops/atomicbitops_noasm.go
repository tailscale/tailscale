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

//go:build !amd64 && !arm64
// +build !amd64,!arm64

package atomicbitops

import (
	"sync/atomic"
)

//go:nosplit
func AndUint32(addr *uint32, val uint32) {
	for {
		o := atomic.LoadUint32(addr)
		n := o & val
		if atomic.CompareAndSwapUint32(addr, o, n) {
			break
		}
	}
}

//go:nosplit
func OrUint32(addr *uint32, val uint32) {
	for {
		o := atomic.LoadUint32(addr)
		n := o | val
		if atomic.CompareAndSwapUint32(addr, o, n) {
			break
		}
	}
}

//go:nosplit
func XorUint32(addr *uint32, val uint32) {
	for {
		o := atomic.LoadUint32(addr)
		n := o ^ val
		if atomic.CompareAndSwapUint32(addr, o, n) {
			break
		}
	}
}

//go:nosplit
func CompareAndSwapUint32(addr *uint32, old, new uint32) (prev uint32) {
	for {
		prev = atomic.LoadUint32(addr)
		if prev != old {
			return
		}
		if atomic.CompareAndSwapUint32(addr, old, new) {
			return
		}
	}
}

//go:nosplit
func AndUint64(addr *uint64, val uint64) {
	for {
		o := atomic.LoadUint64(addr)
		n := o & val
		if atomic.CompareAndSwapUint64(addr, o, n) {
			break
		}
	}
}

//go:nosplit
func OrUint64(addr *uint64, val uint64) {
	for {
		o := atomic.LoadUint64(addr)
		n := o | val
		if atomic.CompareAndSwapUint64(addr, o, n) {
			break
		}
	}
}

//go:nosplit
func XorUint64(addr *uint64, val uint64) {
	for {
		o := atomic.LoadUint64(addr)
		n := o ^ val
		if atomic.CompareAndSwapUint64(addr, o, n) {
			break
		}
	}
}

//go:nosplit
func CompareAndSwapUint64(addr *uint64, old, new uint64) (prev uint64) {
	for {
		prev = atomic.LoadUint64(addr)
		if prev != old {
			return
		}
		if atomic.CompareAndSwapUint64(addr, old, new) {
			return
		}
	}
}
