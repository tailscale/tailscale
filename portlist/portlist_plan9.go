// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package portlist

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"time"
)

func init() {
	newOSImpl = newPlan9Impl

	pollInterval = 5 * time.Second
}

type plan9Impl struct {
	known map[protoPort]*portMeta // inode string => metadata

	br               *bufio.Reader // reused
	portsBuf         []Port
	includeLocalhost bool
}

type protoPort struct {
	proto string
	port  uint16
}

type portMeta struct {
	port Port
	keep bool
}

func newPlan9Impl(includeLocalhost bool) osImpl {
	return &plan9Impl{
		known:            map[protoPort]*portMeta{},
		br:               bufio.NewReader(bytes.NewReader(nil)),
		includeLocalhost: includeLocalhost,
	}
}

func (*plan9Impl) Close() error { return nil }

func (im *plan9Impl) AppendListeningPorts(base []Port) ([]Port, error) {
	ret := base

	des, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, de := range des {
		if !de.IsDir() {
			continue
		}
		pidStr := de.Name()
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		st, _ := os.ReadFile("/proc/" + pidStr + "/fd")
		if !bytes.Contains(st, []byte("/net/tcp/clone")) {
			continue
		}
		args, _ := os.ReadFile("/proc/" + pidStr + "/args")
		procName := string(bytes.TrimSpace(args))
		// term% cat /proc/417/fd
		// /usr/glenda
		//   0 r  M   35 (0000000000000001 0 00) 16384      260 /dev/cons
		//   1 w  c    0 (000000000000000a 0 00)     0      471 /dev/null
		//   2 w  M   35 (0000000000000001 0 00) 16384      108 /dev/cons
		//   3 rw I    0 (000000000000002c 0 00)     0       14 /net/tcp/clone
		for line := range bytes.Lines(st) {
			if !bytes.Contains(line, []byte("/net/tcp/clone")) {
				continue
			}
			f := strings.Fields(string(line))
			if len(f) < 10 {
				continue
			}
			if f[9] != "/net/tcp/clone" {
				continue
			}
			qid, err := strconv.ParseUint(strings.TrimPrefix(f[4], "("), 16, 64)
			if err != nil {
				continue
			}
			tcpN := (qid >> 5) & (1<<12 - 1)
			tcpNStr := strconv.FormatUint(tcpN, 10)
			st, _ := os.ReadFile("/net/tcp/" + tcpNStr + "/status")
			if !bytes.Contains(st, []byte("Listen ")) {
				// Unexpected. Or a race.
				continue
			}
			bl, _ := os.ReadFile("/net/tcp/" + tcpNStr + "/local")
			i := bytes.LastIndexByte(bl, '!')
			if i == -1 {
				continue
			}
			if bytes.HasPrefix(bl, []byte("127.0.0.1!")) && !im.includeLocalhost {
				continue
			}
			portStr := strings.TrimSpace(string(bl[i+1:]))
			port, _ := strconv.Atoi(portStr)
			if port == 0 {
				continue
			}
			ret = append(ret, Port{
				Proto:   "tcp",
				Port:    uint16(port),
				Process: procName,
				Pid:     pid,
			})
		}
	}

	return sortAndDedup(ret), nil
}
