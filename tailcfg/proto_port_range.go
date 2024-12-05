// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailcfg

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"tailscale.com/types/ipproto"
	"tailscale.com/util/vizerror"
)

var (
	errEmptyProtocol = errors.New("empty protocol")
	errEmptyString   = errors.New("empty string")
)

// ProtoPortRange is used to encode "proto:port" format.
// The following formats are supported:
//
//	"*" allows all TCP, UDP and ICMP traffic on all ports.
//	"<ports>" allows all TCP, UDP and ICMP traffic on the specified ports.
//	"proto:*" allows traffic of the specified proto on all ports.
//	"proto:<port>" allows traffic of the specified proto on the specified port.
//
// Ports are either a single port number or a range of ports (e.g. "80-90").
// String named protocols support names that ipproto.Proto accepts.
type ProtoPortRange struct {
	// Proto is the IP protocol number.
	// If Proto is 0, it means TCP+UDP+ICMP(4+6).
	Proto int
	Ports PortRange
}

// UnmarshalText implements the encoding.TextUnmarshaler interface. See
// ProtoPortRange for the format.
func (ppr *ProtoPortRange) UnmarshalText(text []byte) error {
	ppr2, err := parseProtoPortRange(string(text))
	if err != nil {
		return err
	}
	*ppr = *ppr2
	return nil
}

// MarshalText implements the encoding.TextMarshaler interface. See
// ProtoPortRange for the format.
func (ppr *ProtoPortRange) MarshalText() ([]byte, error) {
	if ppr.Proto == 0 && ppr.Ports == (PortRange{}) {
		return []byte{}, nil
	}
	return []byte(ppr.String()), nil
}

// String implements the stringer interface. See ProtoPortRange for the
// format.
func (ppr ProtoPortRange) String() string {
	if ppr.Proto == 0 {
		if ppr.Ports == PortRangeAny {
			return "*"
		}
	}
	var buf strings.Builder
	if ppr.Proto != 0 {
		// Proto.MarshalText is infallible.
		text, _ := ipproto.Proto(ppr.Proto).MarshalText()
		buf.Write(text)
		buf.Write([]byte(":"))
	}
	pr := ppr.Ports
	if pr.First == pr.Last {
		fmt.Fprintf(&buf, "%d", pr.First)
	} else if pr == PortRangeAny {
		buf.WriteByte('*')
	} else {
		fmt.Fprintf(&buf, "%d-%d", pr.First, pr.Last)
	}
	return buf.String()
}

// ParseProtoPortRanges parses a slice of IP port range fields.
func ParseProtoPortRanges(ips []string) ([]ProtoPortRange, error) {
	var out []ProtoPortRange
	for _, p := range ips {
		ppr, err := parseProtoPortRange(p)
		if err != nil {
			return nil, err
		}
		out = append(out, *ppr)
	}
	return out, nil
}

func parseProtoPortRange(ipProtoPort string) (*ProtoPortRange, error) {
	if ipProtoPort == "" {
		return nil, errEmptyString
	}
	if ipProtoPort == "*" {
		return &ProtoPortRange{Ports: PortRangeAny}, nil
	}
	if !strings.Contains(ipProtoPort, ":") {
		ipProtoPort = "*:" + ipProtoPort
	}
	protoStr, portRange, err := parseHostPortRange(ipProtoPort)
	if err != nil {
		return nil, err
	}
	if protoStr == "" {
		return nil, errEmptyProtocol
	}

	ppr := &ProtoPortRange{
		Ports: portRange,
	}
	if protoStr == "*" {
		return ppr, nil
	}
	var ipProto ipproto.Proto
	if err := ipProto.UnmarshalText([]byte(protoStr)); err != nil {
		return nil, err
	}
	ppr.Proto = int(ipProto)
	return ppr, nil
}

// parseHostPortRange parses hostport as HOST:PORTS where HOST is
// returned unchanged and PORTS is is either "*" or PORTLOW-PORTHIGH ranges.
func parseHostPortRange(hostport string) (host string, ports PortRange, err error) {
	hostport = strings.ToLower(hostport)
	colon := strings.LastIndexByte(hostport, ':')
	if colon < 0 {
		return "", ports, vizerror.New("hostport must contain a colon (\":\")")
	}
	host = hostport[:colon]
	portlist := hostport[colon+1:]

	if strings.Contains(host, ",") {
		return "", ports, vizerror.New("host cannot contain a comma (\",\")")
	}

	if portlist == "*" {
		// Special case: permit hostname:* as a port wildcard.
		return host, PortRangeAny, nil
	}

	if len(portlist) == 0 {
		return "", ports, vizerror.Errorf("invalid port list: %#v", portlist)
	}

	if strings.Count(portlist, "-") > 1 {
		return "", ports, vizerror.Errorf("port range %#v: too many dashes(-)", portlist)
	}

	firstStr, lastStr, isRange := strings.Cut(portlist, "-")

	var first, last uint64
	first, err = strconv.ParseUint(firstStr, 10, 16)
	if err != nil {
		return "", ports, vizerror.Errorf("port range %#v: invalid first integer", portlist)
	}

	if isRange {
		last, err = strconv.ParseUint(lastStr, 10, 16)
		if err != nil {
			return "", ports, vizerror.Errorf("port range %#v: invalid last integer", portlist)
		}
	} else {
		last = first
	}

	if first == 0 {
		return "", ports, vizerror.Errorf("port range %#v: first port must be >0, or use '*' for wildcard", portlist)
	}

	if first > last {
		return "", ports, vizerror.Errorf("port range %#v: first port must be >= last port", portlist)
	}

	return host, newPortRange(uint16(first), uint16(last)), nil
}

func newPortRange(first, last uint16) PortRange {
	return PortRange{First: first, Last: last}
}
