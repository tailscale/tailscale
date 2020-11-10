// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

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

type ICMP6Code uint8

const (
	ICMP6NoCode ICMP6Code = 0
)

const icmp6HeaderLength = 4
