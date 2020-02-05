// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"fmt"
	"strings"
)

type Port struct {
	Proto   string
	Port    uint16
	inode   string
	Process string
}

type List []Port

var protos = []string{"tcp", "udp"}

func (a *Port) lessThan(b *Port) bool {
	if a.Port < b.Port {
		return true
	} else if a.Port > b.Port {
		return false
	}

	if a.Proto < b.Proto {
		return true
	} else if a.Proto > b.Proto {
		return false
	}

	if a.inode < b.inode {
		return true
	} else if a.inode > b.inode {
		return false
	}

	if a.Process < b.Process {
		return true
	} else if a.Process > b.Process {
		return false
	}
	return false
}

func (a List) SameInodes(b List) bool {
	if a == nil || b == nil || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Proto != b[i].Proto ||
			a[i].Port != b[i].Port ||
			a[i].inode != b[i].inode {
			return false
		}
	}
	return true
}

func (pl List) String() string {
	out := []string{}
	for _, v := range pl {
		out = append(out, fmt.Sprintf("%-3s %5d %-17s %#v",
			v.Proto, v.Port, v.inode, v.Process))
	}
	return strings.Join(out, "\n")
}

func GetList(prev List) (List, error) {
	pl, err := listPorts()
	if err != nil {
		return nil, fmt.Errorf("listPorts: %s", err)
	}
	if pl.SameInodes(prev) {
		// Nothing changed, skip inode lookup
		return prev, nil
	}
	pl, err = addProcesses(pl)
	if err != nil {
		return nil, fmt.Errorf("addProcesses: %s", err)
	}
	return pl, nil
}
