// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"encoding/json"
	"testing"
)

func TestParsePort(t *testing.T) {
	type InOut struct {
		in     string
		expect int
	}
	tests := []InOut{
		{"1.2.3.4:5678", 5678},
		{"0.0.0.0.999", 999},
		{"1.2.3.4:*", 0},
		{"5.5.5.5:0", 0},
		{"[1::2]:5", 5},
		{"[1::2].5", 5},
		{"gibberish", -1},
	}

	for _, io := range tests {
		got := parsePort(io.in)
		if got != io.expect {
			t.Fatalf("input:%#v expect:%v got:%v\n", io.in, io.expect, got)
		}
	}
}

const netstatOutput = `
// linux
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
udp        0      0 0.0.0.0:5353            0.0.0.0:*                          
udp6       0      0 :::5353                 :::*                               
udp6       0      0 :::5354                 :::*                               

// macOS
tcp4       0      0  *.23                   *.*                    LISTEN     
tcp6       0      0  *.24                   *.*                    LISTEN
tcp4      0      0  *.8185                 *.*                    LISTEN
tcp4       0      0  127.0.0.1.8186         *.*                    LISTEN
tcp6       0      0  ::1.8187               *.*                    LISTEN
tcp4       0      0  127.1.2.3.8188         *.*                    LISTEN

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
	want := List{
		Port{"tcp", 22, "", ""},
		Port{"tcp", 23, "", ""},
		Port{"tcp", 24, "", ""},
		Port{"tcp", 32, "sshd", ""},
		Port{"udp", 53, "chrome", ""},
		Port{"udp", 53, "funball", ""},
		Port{"udp", 5050, "CDPSvc", ""},
		Port{"udp", 5353, "", ""},
		Port{"udp", 5354, "", ""},
		Port{"udp", 5453, "", ""},
		Port{"udp", 5553, "", ""},
		Port{"tcp", 8185, "", ""}, // but not 8186, 8187, 8188 on localhost
		Port{"udp", 9353, "iTunes", ""},
	}

	pl := parsePortsNetstat(netstatOutput)
	jgot, _ := json.MarshalIndent(pl, "", "\t")
	jwant, _ := json.MarshalIndent(want, "", "\t")
	if len(pl) != len(want) {
		t.Fatalf("Got:\n%s\n\nWant:\n%s\n", jgot, jwant)
	}
	for i := range pl {
		if pl[i] != want[i] {
			t.Errorf("row#%d\n got: %#v\n\nwant: %#v\n",
				i, pl[i], want[i])
			t.Fatalf("Got:\n%s\n\nWant:\n%s\n", jgot, jwant)
		}
	}
}
