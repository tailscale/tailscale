// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	jsonv1 "encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"time"
)

type qmpSock struct {
	conn   net.Conn
	dec    *jsonv1.Decoder
	enc    *jsonv1.Encoder
	nextID uint64
}

func dialQMPSocket(sockPath string) (*qmpSock, error) {
	// Wait for the QMP socket to appear.
	var q qmpSock
	for range 50 {
		var err error
		q.conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if q.conn == nil {
		return nil, fmt.Errorf("QMP socket %s not available", sockPath)
	}
	q.conn.SetDeadline(time.Now().Add(20 * time.Second))

	// Read the QMP greeting.
	var greeting jsonv1.RawMessage
	q.dec = jsonv1.NewDecoder(q.conn)
	if err := q.dec.Decode(&greeting); err != nil {
		q.conn.Close()
		return nil, fmt.Errorf("reading QMP greeting: %w", err)
	}
	q.enc = jsonv1.NewEncoder(q.conn)

	// Send qmp_capabilities to initialize.
	_, err := q.execute[struct{}](&qmpCommand{Execute: "qmp_capabilities"})
	if err != nil {
		q.conn.Close()
		return nil, fmt.Errorf("reading qmp_capabilities response: %w", err)
	}

	return &q, nil
}

type qmpCommand struct {
	Execute   string `json:"execute"`
	Arguments any    `json:"arguments,omitzero"`
	ID        uint64 `json:"id,omitzero"`
}

type qmpError struct {
	Class string `json:"class"`
	Desc  string `json:"desc"`
}

func (e *qmpError) Error() string { return e.Class + ": " + e.Desc }

type qmpResponse[T any] struct {
	Return T                 `json:"return"`
	Error  *qmpError         `json:"error"`
	ID     uint64            `json:"id"`
	Event  string            `json:"event"`
	QMP    jsonv1.RawMessage `json:"QMP"`
}

// execute sends a command over the QMP socket to the vm. Other messages can
// appear on the socket, especially events. These are filtered out.
// execute is the only command we currently support. There is an exec-oob in
// the spec that we could implement but it would require rewiring the return
// message handling.
// execute is not safe to use concurrently on the same qmpSock.
func (q *qmpSock) execute[T any](cmd *qmpCommand) (*qmpResponse[T], error) {
	// Copy the command as we are mutating it with the ID.
	q.nextID++
	sendCmd := *cmd
	sendCmd.ID = q.nextID

	if err := q.enc.Encode(sendCmd); err != nil {
		return nil, err
	}

	for {
		var resp qmpResponse[T]
		if err := q.dec.Decode(&resp); err != nil {
			return nil, err
		}
		switch {
		case resp.QMP != nil:
			// Only set on server greeting, getting it here is bad.
			return nil, fmt.Errorf("%s: unexpected QMP greeting mid-session", sendCmd.Execute)
		case resp.Event != "":
			if slices.Contains([]string{"RESET", "SHUTDOWN", "STOP"}, resp.Event) {
				return nil, fmt.Errorf("got closing QMP event: %s", resp.Event)
			}
			// Do not care about async events, skip this.
			continue
		case resp.Error != nil:
			// If it is our error report it, if not, continue.
			if resp.ID == sendCmd.ID {
				return &resp, fmt.Errorf("%s: %w", sendCmd.Execute, resp.Error)
			}
			continue
		case resp.ID != sendCmd.ID:
			// Not our message.
			continue
		default:
			return &resp, nil
		}
	}
}

func (q *qmpSock) close() {
	if q == nil {
		return
	}
	q.conn.Close()
}

// hostFwdRe matches a single TCP[HOST_FORWARD] line from QEMU's
// "info usernet" human-monitor command output, e.g.:
//
//	TCP[HOST_FORWARD]  12       127.0.0.1 35323       10.0.2.15    22
var hostFwdRe = regexp.MustCompile(`TCP\[HOST_FORWARD\]\s+\d+\s+127\.0\.0\.1\s+(\d+)\s+`)

type qmpHumanMonitorCommand struct {
	CommandLine string `json:"command-line"`
}

// qmpQueryHostFwd connects to a QEMU QMP socket and queries the host port
// assigned to the first TCP host forward rule (the SSH debug port).
func qmpQueryHostFwd(n *Node) (int, error) {
	q, err := dialQMPSocket(n.qmpPath)
	if err != nil {
		return 0, fmt.Errorf("error opening qmp connection: %w", err)
	}
	defer q.close()

	// Poll "info usernet" until the SLIRP host-forward rule appears.
	// On slow runners (e.g. GitHub Actions) QEMU sometimes returns an
	// empty "info usernet" if we query it before user-mode networking
	// has finished wiring up the forward, so single-shot lookups fail.
	// TODO(cmol): "human-monitor-command" is an unstable interface and its usage
	// is discouraged, but the existing "x-query-usernet" is experimental. Switch
	// to "x-query-usernet" once the experimental label goes away:
	// https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#command-QMP-net.x-query-usernet
	deadline := time.Now().Add(10 * time.Second)
	var lastReturn string
	for {
		resp, err := q.execute[string](&qmpCommand{
			Execute:   "human-monitor-command",
			Arguments: qmpHumanMonitorCommand{CommandLine: "info usernet"},
		})
		if err != nil {
			return 0, fmt.Errorf("reading info usernet response: %w", err)
		}
		lastReturn = resp.Return
		if m := hostFwdRe.FindStringSubmatch(lastReturn); m != nil {
			return strconv.Atoi(m[1])
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0, fmt.Errorf("no hostfwd port found after waiting: %q", lastReturn)
}

type setLinkArgs struct {
	Name string `json:"name"`
	Up   bool   `json:"up"`
}

func (e *Env) setLink(n *Node, i int, up bool) error {
	q, err := dialQMPSocket(n.qmpPath)
	if err != nil {
		return fmt.Errorf("error opening qmp connection: %w", err)
	}
	defer q.close()

	resp, err := q.execute[struct{}](&qmpCommand{
		Execute: "set_link",
		Arguments: setLinkArgs{
			Name: fmt.Sprintf("net%d", i),
			Up:   up,
		},
	})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("set_link %s: %s: %s", fmt.Sprintf("net%d", i),
			resp.Error.Class, resp.Error.Desc)
	}
	return nil
}
