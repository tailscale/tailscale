// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"net"
	"testing"

	"tailscale.com/tstest"
)

func TestGetList(t *testing.T) {
	tstest.ResourceCheck(t)

	pl, err := getList(nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range pl {
		t.Logf("[%d] %+v", i, p)
	}
	t.Logf("As String: %v", pl.String())
}

func TestIgnoreLocallyBoundPorts(t *testing.T) {
	tstest.ResourceCheck(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("failed to bind: %v", err)
	}
	defer ln.Close()
	ta := ln.Addr().(*net.TCPAddr)
	port := ta.Port
	pl, err := getList(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pl {
		if p.Proto == "tcp" && int(p.Port) == port {
			t.Fatal("didn't expect to find test's localhost ephemeral port")
		}
	}
}

func TestLessThan(t *testing.T) {
	tests := []struct {
		name string
		a, b Port
		want bool
	}{
		{
			"Port a < b",
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			Port{Proto: "tcp", Port: 101, Process: "proc1", inode: "inode1"},
			true,
		},
		{
			"Port a > b",
			Port{Proto: "tcp", Port: 101, Process: "proc1", inode: "inode1"},
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			false,
		},
		{
			"Proto a < b",
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			Port{Proto: "udp", Port: 100, Process: "proc1", inode: "inode1"},
			true,
		},
		{
			"Proto a < b",
			Port{Proto: "udp", Port: 100, Process: "proc1", inode: "inode1"},
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			false,
		},
		{
			"inode a < b",
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode2"},
			true,
		},
		{
			"inode a > b",
			Port{Proto: "tcp", Port: 100, Process: "proc2", inode: "inode2"},
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			false,
		},
		{
			"Process a < b",
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			Port{Proto: "tcp", Port: 100, Process: "proc2", inode: "inode1"},
			true,
		},
		{
			"Process a > b",
			Port{Proto: "tcp", Port: 100, Process: "proc2", inode: "inode1"},
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			false,
		},
		{
			"Port evaluated first",
			Port{Proto: "udp", Port: 100, Process: "proc2", inode: "inode2"},
			Port{Proto: "tcp", Port: 101, Process: "proc1", inode: "inode1"},
			true,
		},
		{
			"Proto evaluated second",
			Port{Proto: "tcp", Port: 100, Process: "proc2", inode: "inode2"},
			Port{Proto: "udp", Port: 100, Process: "proc1", inode: "inode1"},
			true,
		},
		{
			"inode evaluated third",
			Port{Proto: "tcp", Port: 100, Process: "proc2", inode: "inode1"},
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode2"},
			true,
		},
		{
			"Process evaluated fourth",
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			Port{Proto: "tcp", Port: 100, Process: "proc2", inode: "inode1"},
			true,
		},
		{
			"equal",
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			Port{Proto: "tcp", Port: 100, Process: "proc1", inode: "inode1"},
			false,
		},
	}

	for _, tt := range tests {
		got := tt.a.lessThan(&tt.b)
		if got != tt.want {
			t.Errorf("%s: Equal = %v; want %v", tt.name, got, tt.want)
		}
	}
}

func TestSameInodes(t *testing.T) {
	port1 := Port{Proto: "tcp", Port: 100, Process: "proc", inode: "inode1"}
	port2 := Port{Proto: "tcp", Port: 100, Process: "proc", inode: "inode1"}
	portProto := Port{Proto: "udp", Port: 100, Process: "proc", inode: "inode1"}
	portPort := Port{Proto: "tcp", Port: 101, Process: "proc", inode: "inode1"}
	portInode := Port{Proto: "tcp", Port: 100, Process: "proc", inode: "inode2"}
	portProcess := Port{Proto: "tcp", Port: 100, Process: "other", inode: "inode1"}

	tests := []struct {
		name string
		a, b List
		want bool
	}{
		{
			"identical",
			List{port1, port1},
			List{port2, port2},
			true,
		},
		{
			"proto differs",
			List{port1, port1},
			List{port2, portProto},
			false,
		},
		{
			"port differs",
			List{port1, port1},
			List{port2, portPort},
			false,
		},
		{
			"inode differs",
			List{port1, port1},
			List{port2, portInode},
			false,
		},
		{
			// SameInodes does not check the Process field
			"Process differs",
			List{port1, port1},
			List{port2, portProcess},
			true,
		},
	}
	for _, tt := range tests {
		got := tt.a.sameInodes(tt.b)
		if got != tt.want {
			t.Errorf("%s: Equal = %v; want %v", tt.name, got, tt.want)
		}
	}
}

func BenchmarkGetList(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := getList(nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
