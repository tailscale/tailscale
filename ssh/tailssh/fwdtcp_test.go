// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
	"tailscale.com/tstest"
)

func newFwdTCPTestClient(t *testing.T, allow bool) (*testssh.Client, *userMeta) {
	t.Helper()
	lu := fwdTestIdentity(t)
	exe := makeExecutableReachable(t)
	t.Setenv("TS_TEST_SSH_FWD_PREFIX", strings.Join(testFwdPrefix, " "))
	tstest.Replace(t, &monitorSpawnPrefix, testMonitorPrefix)
	s := &server{
		logf: tstest.WhileTestRunningLogger(t), tailscaledPath: exe,
		lb: &localState{
			sshEnabled: true, varRoot: t.TempDir(),
			matchingRule: &tailcfg.SSHRule{
				SSHUsers:   map[string]string{"alice": lu.Username},
				Action:     &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: allow},
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
			},
		},
	}
	sc, dc := memnet.NewTCPConn(netip.MustParseAddrPort("100.100.100.101:2231"), netip.MustParseAddrPort("100.100.100.102:22"), 1024)
	if err := sc.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	handleDone := make(chan error, 1)
	go func() { handleDone <- s.HandleSSHConn(dc) }()
	t.Cleanup(func() {
		sc.Close()
		dc.Close()
		s.Shutdown()
		select {
		case err := <-handleDone:
			if err != nil {
				t.Errorf("HandleSSHConn: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("SSH handler did not finish")
		}
	})
	cl, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), &testssh.ClientConfig{
		User: "alice", HostKeyCallback: testssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := testssh.NewClient(cl, chans, reqs)
	t.Cleanup(func() { client.Close() })
	return client, lu
}

// Both fixed TCP -L forwards and SOCKS -D requests arrive as direct-tcpip
// channels. In particular, SOCKS domain-name destinations must be resolved
// in the dialer child, so exercise a hostname as well as IPv4 and IPv6.
func TestFwdTCPFullStackHalfClose(t *testing.T) {
	client, _ := newFwdTCPTestClient(t, true)
	for _, kind := range []string{"ipv4", "ipv6", "hostname"} {
		for _, serviceFirst := range []bool{false, true} {
			name := kind + "/client-half-close"
			if serviceFirst {
				name = kind + "/service-half-close"
			}
			t.Run(name, func(t *testing.T) {
				network, addr := "tcp4", "127.0.0.1:0"
				if kind == "ipv6" {
					network, addr = "tcp6", "[::1]:0"
				}
				ln, err := net.Listen(network, addr)
				if err != nil {
					if kind == "ipv6" {
						t.Skipf("IPv6 unavailable: %v", err)
					}
					t.Fatal(err)
				}
				defer ln.Close()
				ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
				host, port, err := net.SplitHostPort(ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				if kind == "hostname" {
					host = "localhost"
				}
				portNum, err := strconv.Atoi(port)
				if err != nil {
					t.Fatal(err)
				}
				ch, reqs, err := client.OpenChannel("direct-tcpip", tcpForwardPayload(host, uint32(portNum)))
				if err != nil {
					t.Fatal(err)
				}
				defer ch.Close()
				go testssh.DiscardRequests(reqs)
				service, err := ln.(*net.TCPListener).AcceptTCP()
				if err != nil {
					t.Fatal(err)
				}
				defer service.Close()
				service.SetDeadline(time.Now().Add(10 * time.Second))
				var first, second interface {
					io.ReadWriteCloser
					CloseWrite() error
				} = ch, service
				if serviceFirst {
					first, second = second, first
				}
				if _, err := io.WriteString(first, "request"); err != nil {
					t.Fatal(err)
				}
				if err := first.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if b, err := io.ReadAll(second); err != nil || string(b) != "request" {
					t.Fatalf("request = %q, %v", b, err)
				}
				if _, err := io.WriteString(second, "response"); err != nil {
					t.Fatal(err)
				}
				if err := second.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if b, err := io.ReadAll(first); err != nil || string(b) != "response" {
					t.Fatalf("response after half-close = %q, %v", b, err)
				}
			})
		}
	}
}

func tcpForwardPayload(host string, port uint32) []byte {
	return testssh.Marshal(&struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{host, port, "127.0.0.1", 12345})
}

func TestFwdTCPDenied(t *testing.T) {
	for _, mode := range []string{"policy", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "disabled" {
				envknob.SetenvForTest(t, "TS_SSH_DISABLE_FORWARDING", "true")
			}
			client, _ := newFwdTCPTestClient(t, mode != "policy")
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			forward, err := client.Dial("tcp", ln.Addr().String())
			if err == nil {
				forward.Close()
				t.Fatal("forwarding unexpectedly allowed")
			}
			var openErr *testssh.OpenChannelError
			if !errors.As(err, &openErr) || openErr.Reason != testssh.Prohibited {
				t.Fatalf("forwarding error = %v; want Prohibited", err)
			}
			ln.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
			if c, err := ln.Accept(); err == nil {
				c.Close()
				t.Fatal("denied forward still dialed the service")
			} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				t.Fatal(err)
			}
		})
	}
}

func TestFwdTCPDialFailure(t *testing.T) {
	client, _ := newFwdTCPTestClient(t, true)
	// Bind without listening, reserving an endpoint that refuses connections
	// without racing another process's reuse of a closed listener's port.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(sa.(*unix.SockaddrInet4).Port)
	for _, payload := range [][]byte{
		{1},
		tcpForwardPayload("127.0.0.1", 0),
		tcpForwardPayload("127.0.0.1", 65536),
		tcpForwardPayload("127.0.0.1", math.MaxUint32),
		tcpForwardPayload("127.0.0.1", port),
	} {
		ch, _, err := client.OpenChannel("direct-tcpip", payload)
		if err == nil {
			ch.Close()
			t.Fatal("invalid or refused dial unexpectedly succeeded")
		}
		var openErr *testssh.OpenChannelError
		if !errors.As(err, &openErr) || openErr.Reason != testssh.ConnectionFailed {
			t.Fatalf("dial error = %v; want ConnectionFailed", err)
		}
	}
	// A failed dial must not tear down the shared monitor or SSH connection.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	forward, err := client.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial after failures: %v", err)
	}
	defer forward.Close()
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	service, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	service.Close()
}

// TestFwdTCPPortRange checks the SSH wire range before policy evaluation or
// child creation. Valid endpoints reach the policy callback, which denies them
// here so no actual destination needs to be listening on boundary ports.
func TestFwdTCPPortRange(t *testing.T) {
	for _, port := range []uint32{0, 1, math.MaxUint16, math.MaxUint16 + 1, math.MaxUint32} {
		t.Run(strconv.FormatUint(uint64(port), 10), func(t *testing.T) {
			valid := port >= 1 && port <= math.MaxUint16
			policyCalled := false
			srv := &gliderssh.Server{
				LocalPortForwardingCallback: func(_ gliderssh.Context, _ string, gotPort uint32) bool {
					policyCalled = true
					if gotPort != port {
						t.Errorf("policy port = %d; want %d", gotPort, port)
					}
					return false
				},
			}
			ch := &tcpPortTestChannel{t: t, payload: tcpForwardPayload("localhost", port)}
			c := new(conn)
			c.fwdDirectTCPIPHandler(srv, nil, ch, nil)
			wantReason := gossh.ConnectionFailed
			if valid {
				wantReason = gossh.Prohibited
			}
			if !ch.rejected || ch.reason != wantReason || policyCalled != valid {
				t.Fatalf("rejected=%v reason=%v policyCalled=%v; want reason=%v policyCalled=%v", ch.rejected, ch.reason, policyCalled, wantReason, valid)
			}
			if c.connMonitorIfAny() != nil {
				t.Fatal("rejected request spawned a monitor")
			}
		})
	}
}

type tcpPortTestChannel struct {
	t        *testing.T
	payload  []byte
	rejected bool
	reason   gossh.RejectionReason
}

func (c *tcpPortTestChannel) ChannelType() string { return "direct-tcpip" }
func (c *tcpPortTestChannel) ExtraData() []byte   { return c.payload }
func (c *tcpPortTestChannel) Accept() (gossh.Channel, <-chan *gossh.Request, error) {
	c.t.Fatal("unexpected channel acceptance")
	return nil, nil, errors.New("unexpected channel acceptance")
}
func (c *tcpPortTestChannel) Reject(reason gossh.RejectionReason, _ string) error {
	c.rejected, c.reason = true, reason
	return nil
}

func TestParseFwdArgsTCPDial(t *testing.T) {
	for _, tt := range []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:443", true},
		{"[::1]:443", true},
		{"[fe80::1%testzone]:443", true}, // scope validation belongs to the child dialer
		{"localhost:443", true},
		{"unresolved.example.invalid:443", true}, // no DNS lookup during shape validation
		{":1", true},                             // retain net.Dial's empty-host behavior
		{"localhost:65535", true},
		{":0", false},
		{"", false},
		{"localhost", false},
		{"localhost:http", false},
		{"localhost:65536", false},
		{"localhost:-1", false},
		{"::1:443", false},
	} {
		t.Run(tt.addr, func(t *testing.T) {
			_, err := parseFwdArgs([]string{"--op=dial", "--net=tcp", "--addr=" + tt.addr, "--fd=3"})
			if (err == nil) != tt.ok {
				t.Fatalf("parse TCP dial %q: %v; want success=%v", tt.addr, err, tt.ok)
			}
		})
	}
}
