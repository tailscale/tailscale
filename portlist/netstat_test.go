// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"fmt"
	"testing"
)

func TestParsePort(t *testing.T) {
	type InOut struct {
		in     string
		expect int
	}
	tests := []InOut{
		InOut{"1.2.3.4:5678", 5678},
		InOut{"0.0.0.0.999", 999},
		InOut{"1.2.3.4:*", 0},
		InOut{"5.5.5.5:0", 0},
		InOut{"[1::2]:5", 5},
		InOut{"[1::2].5", 5},
		InOut{"gibberish", -1},
	}

	for _, io := range tests {
		got := parsePort(io.in)
		if got != io.expect {
			t.Fatalf("input:%#v expect:%v got:%v\n", io.in, io.expect, got)
		}
	}
}

var netstat_output = `
// linux
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
udp        0      0 0.0.0.0:5353            0.0.0.0:*                          
udp6       0      0 :::5353                 :::*                               
udp6       0      0 :::5354                 :::*                               

// macOS
tcp4       0      0  *.23                   *.*                    LISTEN     
tcp6       0      0  *.24                   *.*                    LISTEN     
udp6       0      0  *.5453                 *.*                               
udp4       0      0  *.5553                 *.*                               

// Windows 10
  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:32             0.0.0.0:0              LISTENING
 [sshd.exe]
  UDP    0.0.0.0:5050           *:*
  CDPSvc
 [svchost.exe]
  UDP    0.0.0.0:53             *:*
 [chrome.exe]
  UDP    10.0.1.43:9353         *:*
 [iTunes.exe]
  UDP    [::]:53                *:*
  UDP    [::]:53                *:*
 [funball.exe]
`

func TestParsePortsNetstat(t *testing.T) {
	expect := List{
		Port{"tcp", 22, "", ""},
		Port{"tcp", 23, "", ""},
		Port{"tcp", 24, "", ""},
		Port{"tcp", 32, "", "sshd"},
		Port{"udp", 53, "", "chrome"},
		Port{"udp", 53, "", "funball"},
		Port{"udp", 5050, "", "CDPSvc"},
		Port{"udp", 5353, "", ""},
		Port{"udp", 5354, "", ""},
		Port{"udp", 5453, "", ""},
		Port{"udp", 5553, "", ""},
		Port{"udp", 9353, "", "iTunes"},
	}

	pl := parsePortsNetstat(netstat_output)
	fmt.Printf("--- expect:\n%v\n", expect)
	fmt.Printf("--- got:\n%v\n", pl)
	for i := range pl {
		if expect[i] != pl[i] {
			t.Fatalf("row#%d\n expect=%v\n    got=%v\n",
				i, expect[i], pl[i])
		}
	}
}
