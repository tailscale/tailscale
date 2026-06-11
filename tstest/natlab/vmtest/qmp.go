// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// qmpClient is a minimal client for QEMU's QMP (QEMU Machine Protocol)
// monitor socket. It supports just what the harness needs: the capabilities
// handshake plus simple synchronous commands (stop, cont, query-status,
// human-monitor-command). See
// https://www.qemu.org/docs/master/interop/qmp-spec.html.
type qmpClient struct {
	conn net.Conn
	dec  *json.Decoder
}

// dialQMP connects to the QMP unix socket at sockPath, waiting up to
// dialTimeout for the socket to appear (QEMU creates it asynchronously at
// startup), and performs the protocol handshake (greeting + qmp_capabilities)
// so the returned client is ready to execute commands. The caller must Close
// the client when done; QEMU's QMP chardev accepts one client at a time, so
// holding a client open blocks other dialers.
func dialQMP(sockPath string, dialTimeout time.Duration) (*qmpClient, error) {
	var conn net.Conn
	deadline := time.Now().Add(dialTimeout)
	for {
		var err error
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("QMP socket %s not available: %w", sockPath, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// I/O deadline for the handshake below; command() refreshes it
	// per command, so a qmpClient may be held open indefinitely.
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	c := &qmpClient{conn: conn, dec: json.NewDecoder(conn)}

	// Read the QMP greeting.
	var greeting json.RawMessage
	if err := c.dec.Decode(&greeting); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading QMP greeting: %w", err)
	}
	// Enter command mode.
	if err := c.command("qmp_capabilities", nil, nil); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *qmpClient) Close() error { return c.conn.Close() }

// command executes a single QMP command and decodes its "return" value into
// out (which may be nil to discard it). args, if non-nil, is marshaled as the
// command's "arguments" object. Asynchronous QMP events (such as the STOP and
// RESUME events that the stop/cont commands themselves trigger) are skipped
// while waiting for the command's response.
func (c *qmpClient) command(name string, args, out any) error {
	req := map[string]any{"execute": name}
	if args != nil {
		req["arguments"] = args
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	// Refresh the I/O deadline for this command, so a long-lived client
	// doesn't inherit a stale deadline from dial time or a prior command.
	c.conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.conn.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("writing %s command: %w", name, err)
	}
	for {
		var resp struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Class string `json:"class"`
				Desc  string `json:"desc"`
			} `json:"error"`
			Event string `json:"event"`
		}
		if err := c.dec.Decode(&resp); err != nil {
			return fmt.Errorf("reading %s response: %w", name, err)
		}
		if resp.Event != "" {
			continue // async event, not our response
		}
		if resp.Error != nil {
			return fmt.Errorf("%s: %s: %s", name, resp.Error.Class, resp.Error.Desc)
		}
		if out != nil {
			if err := json.Unmarshal(resp.Return, out); err != nil {
				return fmt.Errorf("decoding %s return value: %w", name, err)
			}
		}
		return nil
	}
}

// vmStatus returns the VM's run state ("running", "paused", ...) via the
// query-status command.
func (c *qmpClient) vmStatus() (string, error) {
	var st struct {
		Running bool   `json:"running"`
		Status  string `json:"status"`
	}
	if err := c.command("query-status", nil, &st); err != nil {
		return "", err
	}
	return st.Status, nil
}

// qmp dials the node's QMP monitor socket. It returns an error for nodes not
// backed by QEMU: macOS/tailmac VMs (Apple Virtualization.framework) have no
// QMP monitor.
func (n *Node) qmp() (*qmpClient, error) {
	if n.qmpSock == "" {
		return nil, fmt.Errorf("node %s (%s) is not QEMU-backed; QMP not supported", n.name, n.os.Name)
	}
	return dialQMP(n.qmpSock, 5*time.Second)
}

// Suspend pauses n's virtual machine via the QMP "stop" command. As seen from
// the network it models a host suspend (a laptop lid close): the guest's
// vCPUs halt, QEMU stops servicing the VM's network devices so packets sent
// to it while stopped are dropped, and the rest of the world (peers, relays,
// DERP, control) keeps running in real time and may expire state that
// references the suspended node — the ingredient needed to reproduce
// suspend-induced path-death bugs like tailscale/tailscale#20082, where a
// peer relay reaps an idle session while one endpoint sleeps.
//
// Guest time behavior (verified empirically by TestSuspendResume): QEMU's
// virtual clock — which drives the guest's clocksources (kvmclock; the HPET
// that the gokrazy kernel is pinned to via clocksource=hpet) and its timer
// devices — pauses while the VM is stopped, and "cont" does not advance it.
// The guest therefore does not observe the stopped interval at all: on
// Resume its CLOCK_MONOTONIC continues where it left off (just as on a real
// suspend) and its timers simply fire late. Unlike a real laptop wake,
// though, the guest receives no resume notification and does not re-read the
// RTC (under the harness's default -rtc behavior, base=utc clock=host, the
// RTC would report real host time if re-read), so the guest's wall clock
// lags real time by the suspend duration until NTP would step it. The
// suspend-bug-relevant asymmetry is the same in both cases: the guest's
// timers are frozen while everyone else's keep counting, so on resume the
// guest experiences the rest of the world having jumped ahead.
//
// Suspend verifies via QMP query-status that the VM actually entered the
// "paused" run state. It is only supported on QEMU-backed nodes (gokrazy and
// cloud images) and fatals the test for macOS/tailmac nodes. Use [Env.Resume]
// to un-pause.
func (e *Env) Suspend(n *Node) {
	e.t.Helper()
	c, err := n.qmp()
	if err != nil {
		e.t.Fatalf("Suspend(%s): %v", n.name, err)
	}
	defer c.Close()
	if err := c.command("stop", nil, nil); err != nil {
		e.t.Fatalf("Suspend(%s): %v", n.name, err)
	}
	st, err := c.vmStatus()
	if err != nil {
		e.t.Fatalf("Suspend(%s): query-status: %v", n.name, err)
	}
	if st != "paused" {
		e.t.Fatalf("Suspend(%s): VM status = %q, want \"paused\"", n.name, st)
	}
	e.t.Logf("[%s] VM suspended (QMP stop; status=%s)", n.name, st)
}

// Resume un-pauses a VM previously paused by [Env.Suspend], via the QMP
// "cont" command, and verifies via query-status that it is running again.
// See [Env.Suspend] for what the guest observes on resume. It fatals the
// test on error, and is only supported on QEMU-backed nodes.
func (e *Env) Resume(n *Node) {
	e.t.Helper()
	c, err := n.qmp()
	if err != nil {
		e.t.Fatalf("Resume(%s): %v", n.name, err)
	}
	defer c.Close()
	if err := c.command("cont", nil, nil); err != nil {
		e.t.Fatalf("Resume(%s): %v", n.name, err)
	}
	st, err := c.vmStatus()
	if err != nil {
		e.t.Fatalf("Resume(%s): query-status: %v", n.name, err)
	}
	if st != "running" {
		e.t.Fatalf("Resume(%s): VM status = %q, want \"running\"", n.name, st)
	}
	e.t.Logf("[%s] VM resumed (QMP cont; status=%s)", n.name, st)
}
