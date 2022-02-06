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

// Package tcp contains internal type definitions that are not expected to be
// used by anyone else outside pkg/tcpip.
package tcp

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// TSOffset is an offset applied to the value of the TSVal field in the TCP
// Timestamp option.
//
// +stateify savable
type TSOffset struct {
	milliseconds uint32
}

// NewTSOffset creates a new TSOffset from milliseconds.
func NewTSOffset(milliseconds uint32) TSOffset {
	return TSOffset{
		milliseconds: milliseconds,
	}
}

// TSVal applies the offset to now and returns the timestamp in milliseconds.
func (offset TSOffset) TSVal(now tcpip.MonotonicTime) uint32 {
	return uint32(now.Sub(tcpip.MonotonicTime{}).Milliseconds()) + offset.milliseconds
}

// Elapsed calculates the elapsed time given now and the echoed back timestamp.
func (offset TSOffset) Elapsed(now tcpip.MonotonicTime, tsEcr uint32) time.Duration {
	return time.Duration(offset.TSVal(now)-tsEcr) * time.Millisecond
}
