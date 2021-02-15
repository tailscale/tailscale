// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin,!redo

package monitor

import (
	"bufio"
	"errors"
	"os/exec"

	"tailscale.com/syncs"
	"tailscale.com/types/logger"
)

// unspecifiedMessage is a minimal message implementation that should not
// be ignored. In general, OS-specific implementations should use better
// types and avoid this if they can.
type unspecifiedMessage struct{}

func (unspecifiedMessage) ignore() bool { return false }

func newOSMon(logf logger.Logf) (osMon, error) {
	return new(routeMonitorSubProcMon), nil
}

// routeMonitorSubProcMon is a very simple (temporary? but I know
// better) monitor implementation for darwin in tailscaled-mode where
// we can just shell out to "route -n monitor". It waits for any input
// but doesn't parse it. Then we poll to see if something is different.
type routeMonitorSubProcMon struct {
	closed syncs.AtomicBool
	cmd    *exec.Cmd // of "/sbin/route -n monitor"
	br     *bufio.Reader
	buf    []byte
}

func (m *routeMonitorSubProcMon) Close() error {
	m.closed.Set(true)
	if m.cmd != nil {
		m.cmd.Process.Kill()
		m.cmd = nil
	}
	return nil
}

func (m *routeMonitorSubProcMon) Receive() (message, error) {
	if m.closed.Get() {
		return nil, errors.New("monitor closed")
	}
	if m.cmd == nil {
		cmd := exec.Command("/sbin/route", "-n", "monitor")
		outPipe, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		m.br = bufio.NewReader(outPipe)
		m.cmd = cmd
		m.buf = make([]byte, 16<<10)
	}
	_, err := m.br.Read(m.buf)
	if err != nil {
		m.Close()
		return nil, err
	}
	return unspecifiedMessage{}, nil
}
