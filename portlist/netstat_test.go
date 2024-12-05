// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package portlist

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"go4.org/mem"
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
		got := parsePort(mem.S(io.in))
		if got != io.expect {
			t.Fatalf("input:%#v expect:%v got:%v\n", io.in, io.expect, got)
		}
	}
}

const netstatOutput = `
// macOS
tcp4       0      0  *.23                   *.*                    LISTEN     
tcp6       0      0  *.24                   *.*                    LISTEN
tcp4      0      0  *.8185                 *.*                    LISTEN
tcp4       0      0  127.0.0.1.8186         *.*                    LISTEN
tcp6       0      0  ::1.8187               *.*                    LISTEN
tcp4       0      0  127.1.2.3.8188         *.*                    LISTEN

udp6       0      0  *.106                 *.*                      
udp4       0      0  *.104                 *.*                      
udp46      0      0  *.146                 *.*                      
`

func TestParsePortsNetstat(t *testing.T) {
	for _, loopBack := range [...]bool{false, true} {
		t.Run(fmt.Sprintf("loopback_%v", loopBack), func(t *testing.T) {
			want := List{
				{"tcp", 23, "", 0},
				{"tcp", 24, "", 0},
				{"udp", 104, "", 0},
				{"udp", 106, "", 0},
				{"udp", 146, "", 0},
				{"tcp", 8185, "", 0}, // but not 8186, 8187, 8188 on localhost, when loopback is false
			}
			if loopBack {
				want = append(want,
					Port{"tcp", 8186, "", 0},
					Port{"tcp", 8187, "", 0},
					Port{"tcp", 8188, "", 0},
				)
			}
			pl, err := appendParsePortsNetstat(nil, bufio.NewReader(strings.NewReader(netstatOutput)), loopBack)
			if err != nil {
				t.Fatal(err)
			}
			pl = sortAndDedup(pl)
			jgot, _ := json.MarshalIndent(pl, "", "\t")
			jwant, _ := json.MarshalIndent(want, "", "\t")
			if len(pl) != len(want) {
				t.Fatalf("Got:\n%s\n\nWant:\n%s\n", jgot, jwant)
			}
			for i := range pl {
				if pl[i] != want[i] {
					t.Errorf("row#%d\n got: %+v\n\nwant: %+v\n",
						i, pl[i], want[i])
					t.Fatalf("Got:\n%s\n\nWant:\n%s\n", jgot, jwant)
				}
			}
		})
	}
}
