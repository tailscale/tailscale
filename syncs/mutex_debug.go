// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_mutex_debug

package syncs

import (
	"bytes"
	"fmt"
	"log"
	"runtime"
	"sync"
	"unsafe"

	"go4.org/mem"
)

// MutexDebugging indicates whether the "ts_mutex_debug" build tag is set
// and mutex debugging is enabled.
const MutexDebugging = true

type Mutex struct {
	sync.Mutex
}

type RWMutex struct {
	sync.RWMutex
}

func RequiresMutex(mu *Mutex) {
	// TODO: check
}

// TODO(bradfitz): actually track stuff when in debug mode.

var bufPool = &sync.Pool{
	New: func() any {
		b := make([]byte, 16<<10)
		return &b
	},
}

func (m *Mutex) Lock() {
	defer m.Mutex.Lock()

	gid := curGoroutineID()

	up := uintptr((unsafe.Pointer)(m))

	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	stack := (*bufp)[:runtime.Stack(*bufp, false)]

	trackMu.Lock()
	defer trackMu.Unlock()
	gid = walkToParent(gid)

	name, ok := mutexName[up]
	if !ok {
		name = "unnamed"
		log.Printf("XXX unregistered Mutex.Lock %p called from:\n%s", m, stack)
	}

	switch name {
	case "ipnlocal.LocalBackend.mu", "wgengine.userspaceEngine.wgLock", "ipnlocal.nodeBackend.mu":
		if bytes.Contains(stack, []byte("wireguard-go/device.(*Device).RoutineReceiveIncoming")) {
			log.Printf("XXX mutex Lock from wireguard land: %s, %s", name, stack)
		}
	}

	gi, ok := goroutines[gid]
	if !ok {
		gi = &goroutineInfo{}
		goroutines[gid] = gi
	}
	gi.holding = append(gi.holding, &heldLock{
		mutexAddr: up,
		name:      name,
	})
	if len(gi.holding) > 1 {
		names := make([]string, 0, len(gi.holding))
		for i, hl := range gi.holding {
			names = append(names, hl.name)

			if i == 0 {
				continue
			}
			lo := lockOrder{
				first:  gi.holding[i-1].name,
				second: hl.name,
			}
			if lockOrders[lo.reverse()] {
				log.Printf("mutex: potential deadlock detected: lock order violation: %q then %q (saw reverse order before); goroutine %d stack:\n%s", lo.first, lo.second, gid, stack)
			} else {
				if _, ok := lockOrders[lo]; !ok {
					log.Printf("XXX learned new lock order: %q then %q", lo.first, lo.second)
					lockOrders[lo] = true
				}
			}
		}
		log.Printf("XXX goroutine %v holding %q", gid, names)
	}
}

func (m *Mutex) Unlock() {
	defer m.Mutex.Unlock()
	up := uintptr((unsafe.Pointer)(m))

	gid := curGoroutineID()
	trackMu.Lock()
	defer trackMu.Unlock()
	gid = walkToParent(gid)

	name, ok := mutexName[up]
	if !ok {
		name = "unnamed"
	}

	gi, ok := goroutines[gid]
	if !ok || len(gi.holding) == 0 {
		log.Printf("mutex: unlock of %p (%s) by goroutine %d with no held locks", m, name, gid)
		return
	}
	last := gi.holding[len(gi.holding)-1]
	if last.mutexAddr != up {
		log.Printf("mutex: unlock of %p (%s) by goroutine %d, but last held lock is %p (%s)", m, name, gid, last.mutexAddr, last.name)
		return
	}
	gi.holding[len(gi.holding)-1] = nil
	gi.holding = gi.holding[:len(gi.holding)-1]
	if len(gi.holding) == 0 {
		delete(goroutines, gid)
	}
}

var (
	trackMu    sync.Mutex
	mutexName  = make(map[uintptr]string)
	goroutines = make(map[uint64]*goroutineInfo)
	parentGID  = make(map[uint64]uint64)  // child goroutine ID -> parent (for ForkJoinGo)
	lockOrders = make(map[lockOrder]bool) // observed lock orderings
)

type lockOrder struct {
	first  string
	second string
}

func (lo lockOrder) reverse() lockOrder {
	return lockOrder{first: lo.second, second: lo.first}
}

type goroutineInfo struct {
	holding []*heldLock
}

type heldLock struct {
	mutexAddr uintptr
	name      string
	// TODO: stack? [16]uintptr?
}

// RegisterMutex registers the given mutex with the given name for
// debugging purposes.
func RegisterMutex(mu *Mutex, name string) {
	trackMu.Lock()
	defer trackMu.Unlock()
	up := uintptr((unsafe.Pointer)(mu))
	mutexName[up] = name
	runtime.AddCleanup(mu, func(up uintptr) {
		trackMu.Lock()
		defer trackMu.Unlock()
		delete(mutexName, up)
	}, up)
}

var littleBuf = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64)
		return &buf
	},
}

var goroutineSpace = []byte("goroutine ")

func curGoroutineID() uint64 {
	bp := littleBuf.Get().(*[]byte)
	defer littleBuf.Put(bp)
	b := *bp
	b = b[:runtime.Stack(b, false)]
	// Parse the 4707 out of "goroutine 4707 ["
	b = bytes.TrimPrefix(b, goroutineSpace)
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		panic(fmt.Sprintf("No space found in %q", b))
	}
	b = b[:i]
	n, err := mem.ParseUint(mem.B(b), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse goroutine ID out of %q: %v", b, err))
	}
	return n
}

func trackForkJoinPair(parent, child uint64, add bool) {
	trackMu.Lock()
	defer trackMu.Unlock()
	if add {
		parentGID[child] = parent
	} else {
		delete(parentGID, child)
	}
}

func walkToParent(gid uint64) uint64 {
	for {
		p, ok := parentGID[gid]
		if !ok {
			return gid
		}
		gid = p
	}
}

// ForkJoinGo is like go fn() but indicates that the goroutine
// is part of a fork-join parallelism pattern.
//
// This compiles to just "go fn()" in non-debug builds.
func ForkJoinGo(fn func()) {
	parentGID := curGoroutineID()
	go func() {
		childGID := curGoroutineID()
		trackForkJoinPair(parentGID, childGID, true)
		defer trackForkJoinPair(parentGID, childGID, false)
		fn()
	}()
}
