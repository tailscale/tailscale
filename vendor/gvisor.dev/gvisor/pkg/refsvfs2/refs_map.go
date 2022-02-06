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

package refsvfs2

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/log"
	refs_vfs1 "gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
)

var (
	// liveObjects is a global map of reference-counted objects. Objects are
	// inserted when leak check is enabled, and they are removed when they are
	// destroyed. It is protected by liveObjectsMu.
	liveObjects   map[CheckedObject]struct{}
	liveObjectsMu sync.Mutex
)

// CheckedObject represents a reference-counted object with an informative
// leak detection message.
type CheckedObject interface {
	// RefType is the type of the reference-counted object.
	RefType() string

	// LeakMessage supplies a warning to be printed upon leak detection.
	LeakMessage() string

	// LogRefs indicates whether reference-related events should be logged.
	LogRefs() bool
}

func init() {
	liveObjects = make(map[CheckedObject]struct{})
}

// leakCheckEnabled returns whether leak checking is enabled. The following
// functions should only be called if it returns true.
func leakCheckEnabled() bool {
	return refs_vfs1.GetLeakMode() != refs_vfs1.NoLeakChecking
}

// leakCheckPanicEnabled returns whether DoLeakCheck() should panic when leaks
// are detected.
func leakCheckPanicEnabled() bool {
	return refs_vfs1.GetLeakMode() == refs_vfs1.LeaksPanic
}

// Register adds obj to the live object map.
func Register(obj CheckedObject) {
	if leakCheckEnabled() {
		liveObjectsMu.Lock()
		if _, ok := liveObjects[obj]; ok {
			panic(fmt.Sprintf("Unexpected entry in leak checking map: reference %p already added", obj))
		}
		liveObjects[obj] = struct{}{}
		liveObjectsMu.Unlock()
		if leakCheckEnabled() && obj.LogRefs() {
			logEvent(obj, "registered")
		}
	}
}

// Unregister removes obj from the live object map.
func Unregister(obj CheckedObject) {
	if leakCheckEnabled() {
		liveObjectsMu.Lock()
		defer liveObjectsMu.Unlock()
		if _, ok := liveObjects[obj]; !ok {
			panic(fmt.Sprintf("Expected to find entry in leak checking map for reference %p", obj))
		}
		delete(liveObjects, obj)
		if leakCheckEnabled() && obj.LogRefs() {
			logEvent(obj, "unregistered")
		}
	}
}

// LogIncRef logs a reference increment.
func LogIncRef(obj CheckedObject, refs int64) {
	if leakCheckEnabled() && obj.LogRefs() {
		logEvent(obj, fmt.Sprintf("IncRef to %d", refs))
	}
}

// LogTryIncRef logs a successful TryIncRef call.
func LogTryIncRef(obj CheckedObject, refs int64) {
	if leakCheckEnabled() && obj.LogRefs() {
		logEvent(obj, fmt.Sprintf("TryIncRef to %d", refs))
	}
}

// LogDecRef logs a reference decrement.
func LogDecRef(obj CheckedObject, refs int64) {
	if leakCheckEnabled() && obj.LogRefs() {
		logEvent(obj, fmt.Sprintf("DecRef to %d", refs))
	}
}

// logEvent logs a message for the given reference-counted object.
//
// obj.LogRefs() should be checked before calling logEvent, in order to avoid
// calling any text processing needed to evaluate msg.
func logEvent(obj CheckedObject, msg string) {
	log.Infof("[%s %p] %s:\n%s", obj.RefType(), obj, msg, refs_vfs1.FormatStack(refs_vfs1.RecordStack()))
}

// checkOnce makes sure that leak checking is only done once. DoLeakCheck is
// called from multiple places (which may overlap) to cover different sandbox
// exit scenarios.
var checkOnce sync.Once

// DoLeakCheck iterates through the live object map and logs a message for each
// object. It is called once no reference-counted objects should be reachable
// anymore, at which point anything left in the map is considered a leak.
func DoLeakCheck() {
	if leakCheckEnabled() {
		checkOnce.Do(func() {
			liveObjectsMu.Lock()
			defer liveObjectsMu.Unlock()
			leaked := len(liveObjects)
			if leaked > 0 {
				msg := fmt.Sprintf("Leak checking detected %d leaked objects:\n", leaked)
				for obj := range liveObjects {
					msg += obj.LeakMessage() + "\n"
				}
				if leakCheckPanicEnabled() {
					panic(msg)
				}
				log.Warningf(msg)
			}
		})
	}
}
