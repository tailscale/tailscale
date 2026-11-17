// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest"
)

// TestFwdTCPFullStackSocketOwner checks the UID Linux associates with the
// outgoing socket, as used by UID-based firewall rules. TCP has no Unix-style
// per-message credentials; inspect the client half of the exact connection.
func TestFwdTCPFullStackSocketOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to distinguish the daemon from the mapped user")
	}
	client, lu := newFwdTCPTestClient(t, true)
	boundUID, err := strconv.Atoi(lu.Uid)
	if err != nil || boundUID == os.Getuid() {
		t.Fatalf("test requires a distinct bound UID: %q, %v", lu.Uid, err)
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			addr := "127.0.0.1:0"
			if network == "tcp6" {
				addr = "[::1]:0"
			}
			ln, err := net.Listen(network, addr)
			if err != nil {
				if network == "tcp6" {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer ln.Close()
			ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))

			// A direct dial from this process is a control for the UID
			// observation, independent of the SSH forwarding code.
			direct, err := net.Dial(network, ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer direct.Close()
			control, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			uid, _, err := tcpPeerSocketOwner(control)
			if err != nil || uid != os.Getuid() {
				t.Fatalf("direct socket UID = %d, err %v; want %d", uid, err, os.Getuid())
			}
			direct.Close()
			control.Close()

			forward, err := client.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer forward.Close()
			service, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			uid, inode, err := tcpPeerSocketOwner(service)
			if err != nil || uid != boundUID || inode == "0" {
				t.Errorf("forwarded socket UID = %d, inode %q, err %v; want mapped UID %d and a live socket (daemon UID %d)", uid, inode, err, boundUID, os.Getuid())
			}
			forward.Close()
			// Keep the service open and silent. Closing only this SSH
			// channel must release the daemon's socket, not just half-close
			// it. An orphaned TCP socket has inode 0 in /proc/net/tcp*.
			if err := tstest.WaitFor(5*time.Second, func() error {
				_, inode, err := tcpPeerSocketOwner(service)
				if os.IsNotExist(err) || err == nil && inode == "0" {
					return nil
				}
				return fmt.Errorf("forwarding socket still held: inode %q, err %v", inode, err)
			}); err != nil {
				t.Error(err)
			}
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				t.Fatalf("SSH transport after channel close: %v", err)
			}
		})
	}
}

// tcpPeerSocketOwner finds the peer's outgoing socket by its exact local and
// remote endpoints. It is only used with loopback listeners in this process's
// network namespace. The inode distinguishes an open socket from an orphan.
func tcpPeerSocketOwner(service net.Conn) (uid int, inode string, err error) {
	local := service.RemoteAddr().(*net.TCPAddr).AddrPort()
	remote := service.LocalAddr().(*net.TCPAddr).AddrPort()
	path := "/proc/net/tcp"
	if local.Addr().Is6() {
		path += "6"
	}
	encode := func(ap netip.AddrPort) string {
		var ip strings.Builder
		b := ap.Addr().AsSlice()
		for i := 0; i < len(b); i += 4 {
			fmt.Fprintf(&ip, "%08X", binary.NativeEndian.Uint32(b[i:i+4]))
		}
		return fmt.Sprintf("%s:%04X", ip.String(), ap.Port())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 9 && fields[1] == encode(local) && fields[2] == encode(remote) {
			uid, err := strconv.Atoi(fields[7])
			return uid, fields[9], err
		}
	}
	return 0, "", os.ErrNotExist
}

// TestFwdTCPDialChildExits verifies that TCP does not retain a relay process:
// the credentialed child exits and is reaped while the handed-off socket is
// still usable for bidirectional data and half-close.
func TestFwdTCPDialChildExits(t *testing.T) {
	uid, gid, groups := fwdBoundIdentity(t)
	mc := startFwdTestMonitor(t, uid, gid, groups)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
	ctx, cancel := testCtx()
	defer cancel()
	client, err := mc.DialTCP(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	service, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	childrenPath := fmt.Sprintf("/proc/%d/task/%d/children", mc.Pid(), mc.Pid())
	if err := tstest.WaitFor(5*time.Second, func() error {
		b, err := os.ReadFile(childrenPath)
		if err != nil {
			return err
		}
		if len(strings.Fields(string(b))) != 0 {
			return fmt.Errorf("TCP dial child still present: %s", b)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	gotUID, inode, err := tcpPeerSocketOwner(service)
	if err != nil || gotUID != uid || inode == "0" {
		t.Fatalf("socket after child exit: UID %d, inode %q, err %v; want UID %d", gotUID, inode, err, uid)
	}
	service.SetDeadline(time.Now().Add(5 * time.Second))
	client.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(service, service)
		service.Close()
		done <- err
	}()
	if _, err := io.WriteString(client, "after child exit"); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(client); err != nil || string(b) != "after child exit" {
		t.Fatalf("echo after child exit = %q, %v", b, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := mc.Ping(ctx); err != nil {
		t.Fatal(err)
	}
}
