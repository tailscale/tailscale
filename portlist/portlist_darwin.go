// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux,!windows

package portlist

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	exec "tailscale.com/tempfork/osexec"
)

// We have to run netstat, which is a bit expensive, so don't do it too often.
const POLL_SECONDS = 5

func listPorts() (List, error) {
	return listPortsNetstat("-na")
}

// In theory, lsof could replace the function of both listPorts() and
// addProcesses(), since it provides a superset of the netstat output.
// However, "netstat -na" runs ~100x faster than lsof on my machine, so
// we should do it only if the list of open ports has actually changed.
//
// TODO(apenwarr): this fails in a macOS sandbox (ie. our usual case).
// We might as well just delete this code if we can't find a solution.
func addProcesses(pl []Port) ([]Port, error) {
	exe, err := exec.LookPath("lsof")
	if err != nil {
		return nil, fmt.Errorf("lsof: lookup: %v", err)
	}
	c := exec.Cmd{
		Path: exe,
		Args: []string{exe, "-F", "-n", "-P", "-O", "-S2", "-T", "-i4", "-i6"},
	}
	output, err := c.Output()
	if err != nil {
		xe, ok := err.(*exec.ExitError)
		stderr := ""
		if ok {
			stderr = strings.TrimSpace(string(xe.Stderr))
		}
		// fails when run in a macOS sandbox, so make this non-fatal.
		log.Printf("portlist: lsof: %v (%q)\n", err, stderr)
		return pl, nil
	}

	type ProtoPort struct {
		proto string
		port  uint16
	}
	m := map[ProtoPort]*Port{}
	for i := range pl {
		pp := ProtoPort{pl[i].Proto, pl[i].Port}
		m[pp] = &pl[i]
	}

	r := bytes.NewReader(output)
	scanner := bufio.NewScanner(r)

	var cmd, proto string
	for scanner.Scan() {
		line := scanner.Text()
		if line[0] == 'p' {
			// starting a new process
			cmd = ""
			proto = ""
		} else if line[0] == 'c' {
			cmd = line[1:len(line)]
		} else if line[0] == 'P' {
			proto = strings.ToLower(line[1:len(line)])
		} else if line[0] == 'n' {
			rest := line[1:len(line)]
			i := strings.Index(rest, "->")
			if i < 0 {
				// a listening port
				port := parsePort(rest)
				if port > 0 {
					pp := ProtoPort{proto, uint16(port)}
					p := m[pp]
					if p != nil {
						p.Process = cmd
					} else {
						fmt.Fprintf(os.Stderr, "weird: missing %v\n", pp)
					}
				}
			}
		}
	}

	return pl, nil
}
