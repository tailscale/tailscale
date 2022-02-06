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

package header

// NDPRouterSolicit is an NDP Router Solicitation message. It will only contain
// the body of an ICMPv6 packet.
//
// See RFC 4861 section 4.1 for more details.
type NDPRouterSolicit []byte

const (
	// NDPRSMinimumSize is the minimum size of a valid NDP Router
	// Solicitation message (body of an ICMPv6 packet).
	NDPRSMinimumSize = 4

	// ndpRSOptionsOffset is the start of the NDP options in an
	// NDPRouterSolicit.
	ndpRSOptionsOffset = 4
)

// Options returns an NDPOptions of the the options body.
func (b NDPRouterSolicit) Options() NDPOptions {
	return NDPOptions(b[ndpRSOptionsOffset:])
}
