// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin && !ios
// +build darwin,!ios

package portlist

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

// We have to run netstat, which is a bit expensive, so don't do it too often.
const pollInterval = 5 * time.Second

func listPorts() (List, error) {
	return listPortsNetstat("-na")
}

var lsofFailed int64 // atomic bool

// In theory, lsof could replace the function of both listPorts() and
// addProcesses(), since it provides a superset of the netstat output.
// However, "netstat -na" runs ~100x faster than lsof on my machine, so
// we should do it only if the list of open ports has actually changed.
//
// This fails in a macOS sandbox (i.e. in the Mac App Store or System
// Extension GUI build), but does at least work in the
// tailscaled-on-macos mode.
func addProcesses(pl []Port) ([]Port, error) {
	if atomic.LoadInt64(&lsofFailed) != 0 {
		// This previously failed in the macOS sandbox, so don't try again.
		return pl, nil
	}
	exe, err := exec.LookPath("lsof")
	if err != nil {
		return nil, fmt.Errorf("lsof: lookup: %v", err)
	}
	output, err := exec.Command(exe, "-F", "-n", "-P", "-O", "-S2", "-T", "-i4", "-i6").Output()
	if err != nil {
		var stderr []byte
		if xe, ok := err.(*exec.ExitError); ok {
			stderr = xe.Stderr
		}
		// fails when run in a macOS sandbox, so make this non-fatal.
		if atomic.CompareAndSwapInt64(&lsofFailed, 0, 1) {
			log.Printf("portlist: can't run lsof in Mac sandbox; omitting process names from service list. Error details: %v, %s", err, bytes.TrimSpace(stderr))
		}
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
		if line == "" {
			continue
		}
		field, val := line[0], line[1:]
		switch field {
		case 'p':
			// starting a new process
			cmd = ""
			proto = ""
		case 'c':
			cmd = val
		case 'P':
			proto = strings.ToLower(val)
		case 'n':
			if strings.Contains(val, "->") {
				continue
			}
			// a listening port
			port := parsePort(val)
			if port > 0 {
				pp := ProtoPort{proto, uint16(port)}
				p := m[pp]
				switch {
				case p != nil:
					p.Process = cmd
				default:
					// ignore: processes and ports come and go
				}
			}
		}
	}

	return pl, nil
}
