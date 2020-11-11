// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

// icmp6HeaderLength is the size of the ICMPv6 packet header, not
// including the outer IP layer or the variable "response data"
// trailer.
const icmp6HeaderLength = 4

// ICMP6Type is an ICMPv6 type, as specified in
// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
type ICMP6Type uint8

const (
	ICMP6Unreachable  ICMP6Type = 1
	ICMP6TimeExceeded ICMP6Type = 3
	ICMP6EchoRequest  ICMP6Type = 128
	ICMP6EchoReply    ICMP6Type = 129
)

func (t ICMP6Type) String() string {
	switch t {
	case ICMP6Unreachable:
		return "Unreachable"
	case ICMP6TimeExceeded:
		return "TimeExceeded"
	case ICMP6EchoRequest:
		return "EchoRequest"
	case ICMP6EchoReply:
		return "EchoReply"
	default:
		return "Unknown"
	}
}

// ICMP6Code is an ICMPv6 code, as specified in
// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
type ICMP6Code uint8

const (
	ICMP6NoCode ICMP6Code = 0
)
