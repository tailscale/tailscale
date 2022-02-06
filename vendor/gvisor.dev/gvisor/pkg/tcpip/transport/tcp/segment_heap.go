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

package tcp

import "container/heap"

type segmentHeap []*segment

var _ heap.Interface = (*segmentHeap)(nil)

// Len returns the length of h.
func (h *segmentHeap) Len() int {
	return len(*h)
}

// Less determines whether the i-th element of h is less than the j-th element.
func (h *segmentHeap) Less(i, j int) bool {
	return (*h)[i].sequenceNumber.LessThan((*h)[j].sequenceNumber)
}

// Swap swaps the i-th and j-th elements of h.
func (h *segmentHeap) Swap(i, j int) {
	(*h)[i], (*h)[j] = (*h)[j], (*h)[i]
}

// Push adds x as the last element of h.
func (h *segmentHeap) Push(x interface{}) {
	*h = append(*h, x.(*segment))
}

// Pop removes the last element of h and returns it.
func (h *segmentHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return x
}
