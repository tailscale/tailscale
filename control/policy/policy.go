// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/tailscale/hujson"
	"net"
	"strconv"
	"strings"
	"tailscale.com/wgengine/filter"
)

type IP = filter.IP

const IPAny = filter.IPAny

type row struct {
	Action string
	Users  []string
	Ports  []string
}

type Policy struct {
	ACLs   []row
	Groups map[string][]string
	Hosts  map[string]IP
}

func lineAndColumn(b []byte, ofs int64) (line, col int) {
	line = 1
	for _, c := range b[:ofs] {
		if c == '\n' {
			col = 1
			line++
		} else {
			col++
		}
	}
	return line, col
}

func betterUnmarshal(b []byte, obj interface{}) error {
	bio := bytes.NewReader(b)
	d := hujson.NewDecoder(bio)
	d.DisallowUnknownFields()
	err := d.Decode(obj)
	if err != nil {
		switch ee := err.(type) {
		case *hujson.SyntaxError:
			row, col := lineAndColumn(b, ee.Offset)
			return fmt.Errorf("line %d col %d: %v", row, col, ee)
		default:
			return fmt.Errorf("parser: %v", err)
		}
	}
	return nil
}

func Parse(acljson string) (*Policy, error) {
	p := &Policy{}
	err := betterUnmarshal([]byte(acljson), p)
	if err != nil {
		return nil, err
	}

	// Check syntax with an empty usermap to start with.
	// The caller might not have a valid usermap at startup, but we still
	// want to check that the acljson doesn't have any syntax errors
	// as early as possible. When the usermap updates later, it won't
	// add any new syntax errors.
	//
	// TODO(apenwarr): change unmarshal code to detect syntax errors above.
	//  Right now some of the sub-objects aren't parsed until .Expand().
	emptyUserMap := make(map[string][]IP)
	_, err = p.Expand(emptyUserMap)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func parseHostPortRange(hostport string) (host string, ports []filter.PortRange, err error) {
	hl := strings.Split(hostport, ":")
	if len(hl) != 2 {
		return "", nil, errors.New("hostport must have exactly one colon(:)")
	}
	host = hl[0]
	portlist := hl[1]

	if portlist == "*" {
		// Special case: permit hostname:* as a port wildcard.
		ports = append(ports, filter.PortRangeAny)
		return host, ports, nil
	}

	pl := strings.Split(portlist, ",")
	for _, pp := range pl {
		if len(pp) == 0 {
			return "", nil, fmt.Errorf("invalid port list: %#v", portlist)
		}

		pr := strings.Split(pp, "-")
		if len(pr) > 2 {
			return "", nil, fmt.Errorf("port range %#v: too many dashes(-)", pp)
		}

		var first, last uint64
		first, err := strconv.ParseUint(pr[0], 10, 16)
		if err != nil {
			return "", nil, fmt.Errorf("port range %#v: invalid first integer", pp)
		}

		if len(pr) >= 2 {
			last, err = strconv.ParseUint(pr[1], 10, 16)
			if err != nil {
				return "", nil, fmt.Errorf("port range %#v: invalid last integer", pp)
			}
		} else {
			last = first
		}

		if first == 0 {
			return "", nil, fmt.Errorf("port range %#v: first port must be >0, or use '*' for wildcard", pp)
		}

		if first > last {
			return "", nil, fmt.Errorf("port range %#v: first port must be >= last port", pp)
		}

		ports = append(ports, filter.PortRange{uint16(first), uint16(last)})
	}

	return host, ports, nil
}

func (p *Policy) Expand(usermap map[string][]IP) (filter.Matches, error) {
	lcusermap := make(map[string][]IP)
	for k, v := range usermap {
		k = strings.ToLower(k)
		lcusermap[k] = v
	}

	for k, userlist := range p.Groups {
		k = strings.ToLower(k)
		if !strings.HasPrefix(k, "group:") {
			return nil, fmt.Errorf("Group[%#v]: group names must start with 'group:'", k)
		}
		for _, u := range userlist {
			uips := lcusermap[u]
			lcusermap[k] = append(lcusermap[k], uips...)
		}
	}

	hosts := p.Hosts

	var out filter.Matches
	for _, acl := range p.ACLs {
		if acl.Action != "accept" {
			return nil, fmt.Errorf("Action=%#v is not supported", acl.Action)
		}

		var srcs []IP
		for _, user := range acl.Users {
			user = strings.ToLower(user)
			if user == "*" {
				srcs = append(srcs, IPAny)
				continue
			} else if strings.Contains(user, "@") ||
				strings.HasPrefix(user, "role:") ||
				strings.HasPrefix(user, "group:") {
				// fine if the requested user doesn't exist.
				// we don't want to crash ACL parsing just
				// because a previously authed user gets
				// deleted. We'll silently ignore it and
				// no firewall rules are needed.
				// TODO(apenwarr): maybe print a warning?
				for _, ip := range lcusermap[user] {
					if ip != IPAny {
						srcs = append(srcs, ip)
					}
				}
			} else {
				return nil, fmt.Errorf("wgengine/filter: invalid username: %q: needs @domain or group: or role:", user)
			}
		}

		var dsts []filter.IPPortRange
		for _, hostport := range acl.Ports {
			host, ports, err := parseHostPortRange(hostport)
			if err != nil {
				return nil, fmt.Errorf("Ports=%#v: %v", hostport, err)
			}
			ip := net.ParseIP(host)
			ipv, ok := hosts[host]
			if ok {
				// matches an alias; ipv is now valid
			} else if ip != nil && ip.IsUnspecified() {
				// For clarity, reject 0.0.0.0 as an input
				return nil, fmt.Errorf("Ports=%#v: to allow all IP addresses, use *:port, not 0.0.0.0:port", hostport)
			} else if ip == nil && host == "*" {
				// User explicitly requested wildcard dst ip
				ipv = IPAny
			} else {
				if ip != nil {
					ip = ip.To4()
				}
				if ip == nil || len(ip) != 4 {
					return nil, fmt.Errorf("Ports=%#v: %#v: invalid IPv4 address", hostport, host)
				}
				ipv = filter.NewIP(ip)
			}

			for _, pr := range ports {
				dsts = append(dsts, filter.IPPortRange{ipv, pr})
			}
		}

		out = append(out, filter.Match{DstPorts: dsts, SrcIPs: srcs})
	}
	return out, nil
}
