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

package refs

// +stateify savable
type savedReference struct {
	obj interface{}
}

func (w *WeakRef) saveObj() savedReference {
	// We load the object directly, because it is typed. This will be
	// serialized and loaded as a typed value.
	return savedReference{w.obj.Load()}
}

func (w *WeakRef) loadObj(v savedReference) {
	// See note above. This will be serialized and loaded typed. So we're okay
	// as long as refs aren't changing during save and load (which they should
	// not be).
	//
	// w.user is loaded before loadObj is called.
	w.init(v.obj.(RefCounter), w.user)
}
