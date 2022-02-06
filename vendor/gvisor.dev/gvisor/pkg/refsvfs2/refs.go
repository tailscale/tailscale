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

// Package refsvfs2 defines an interface for a reference-counted object.
package refsvfs2

import (
	"gvisor.dev/gvisor/pkg/context"
)

// RefCounter is the interface to be implemented by objects that are reference
// counted.
type RefCounter interface {
	// IncRef increments the reference counter on the object.
	IncRef()

	// DecRef decrements the object's reference count. Users of refs_template.Refs
	// may specify a destructor to be called once the reference count reaches zero.
	DecRef(ctx context.Context)
}

// TryRefCounter is like RefCounter but allow the ref increment to be tried.
type TryRefCounter interface {
	RefCounter

	// TryIncRef attempts to increment the reference count, but may fail if all
	// references have already been dropped, in which case it returns false. If
	// true is returned, then a valid reference is now held on the object.
	TryIncRef() bool
}
