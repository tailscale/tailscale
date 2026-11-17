// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tstun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tailscale/netlink"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

var recoveryTestSeq atomic.Uint32

func TestRetryTUNAfterModprobe(t *testing.T) {
	for _, tt := range []struct {
		name              string
		noHook            bool
		hookErr, retryErr error
		wantCalls         []string
		wantErr           error
	}{
		{name: "unset", noHook: true, wantErr: unix.ENOENT},
		{name: "failed", hookErr: unix.EPERM, wantCalls: []string{"modprobe"}, wantErr: unix.ENOENT},
		{name: "retrySucceeded", wantCalls: []string{"modprobe", "create"}},
		{name: "retryFailed", retryErr: unix.EBUSY, wantCalls: []string{"modprobe", "create"}, wantErr: unix.EBUSY},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := NewFake()
			defer fake.Close()
			var calls []string
			hook := func() error { calls = append(calls, "modprobe"); return tt.hookErr }
			if tt.noHook {
				hook = nil
			}
			dev, err := retryTUNAfterModprobe(t.Logf, "test0", func() (tun.Device, error) {
				calls = append(calls, "create")
				if tt.retryErr != nil {
					return nil, tt.retryErr
				}
				return fake, nil
			}, unix.ENOENT, hook)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && dev != fake {
				t.Errorf("device = %v, want fake", dev)
			}
			if tt.wantErr != nil && dev != nil {
				t.Errorf("device on error = %v", dev)
			}
			if !reflect.DeepEqual(calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", calls, tt.wantCalls)
			}
		})
	}
}

func persistentTestTUN(t *testing.T, queues int) (tun.Device, string) {
	t.Helper()
	name := recoveryTestName()
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if queues > 1 {
		flags |= unix.IFF_MULTI_QUEUE
	}
	var fds []int
	defer func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	fail := func(err error) {
		t.Helper()
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrNotExist) {
			t.Skipf("needs /dev/net/tun and CAP_NET_ADMIN: %v", err)
		}
		t.Fatal(err)
	}
	for i := 0; i < queues; i++ {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			fail(err)
		}
		fds = append(fds, fd)
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			t.Fatal(err)
		}
		requestFlags := flags
		if i == 0 {
			requestFlags |= unix.IFF_TUN_EXCL
		}
		ifr.SetUint16(requestFlags)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			fail(err)
		}
	}
	owned := fds
	fds = nil
	dev, _, err := tun.CreateUnmonitoredTUNFromFDs(owned)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	ioctlRecoveryFile(t, dev.File(), func(fd int) error { return unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1) })
	t.Cleanup(func() {
		dev.Close()
		if _, err := net.InterfaceByName(name); err != nil {
			return
		}
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer unix.Close(fd)
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			t.Error(err)
			return
		}
		ifr.SetUint16(flags)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			t.Error(err)
			return
		}
		if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 0); err != nil {
			t.Error(err)
		}
	})
	return dev, name
}

func TestCreateTUNUsesModprobeHook(t *testing.T) {
	calls := 0
	t.Cleanup(modprobeTunHook.SetForTest(func() error {
		calls++
		return errors.New("integrator-supplied module loader failed")
	}))
	// An invalid name exercises the hook without creating a TUN interface.
	dev, err := createTUN(t.Logf, strings.Repeat("x", unix.IFNAMSIZ), 1280, 1)
	if dev != nil {
		dev.Close()
		t.Fatal("created TUN with an invalid name")
	}
	if err == nil {
		t.Fatal("expected creation failure")
	}
	if calls != 1 {
		t.Errorf("module hook called %d times, want 1", calls)
	}
}

func recoveryTestName() string {
	return fmt.Sprintf("tsr%dx%d", os.Getpid()%10000, recoveryTestSeq.Add(1))
}

func ioctlRecoveryFile(t *testing.T, file *os.File, f func(int) error) {
	t.Helper()
	conn, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ioctlErr error
	if err := conn.Control(func(fd uintptr) { ioctlErr = f(int(fd)) }); err != nil {
		t.Fatal(err)
	}
	if ioctlErr != nil {
		t.Fatal(ioctlErr)
	}
}

func TestNewRecoversTUN(t *testing.T) {
	for _, existing := range []int{1, 4} {
		for _, requested := range []int{1, 4} {
			t.Run(fmt.Sprintf("%dto%d", existing, requested), func(t *testing.T) {
				t.Setenv("TS_DEBUG_MAX_QUEUES", strconv.Itoa(requested))
				old, name := persistentTestTUN(t, existing)
				before, err := net.InterfaceByName(name)
				if err != nil {
					t.Fatal(err)
				}
				link, err := netlink.LinkByName(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := netlink.LinkSetUp(link); err != nil {
					t.Fatal(err)
				}
				addr, err := netlink.ParseAddr("198.18.255.254/32")
				if err != nil {
					t.Fatal(err)
				}
				if err := netlink.AddrAdd(link, addr); err != nil {
					t.Fatal(err)
				}
				_, dst, err := net.ParseCIDR("198.19.255.254/32")
				if err != nil {
					t.Fatal(err)
				}
				route := &netlink.Route{LinkIndex: before.Index, Dst: dst, Scope: netlink.SCOPE_LINK}
				if err := netlink.RouteAdd(route); err != nil {
					t.Fatal(err)
				}
				if err := old.Close(); err != nil {
					t.Fatal(err)
				}
				dev, gotName, err := New(t.Logf, name)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dev.Close() })
				if gotName != name {
					t.Errorf("name = %q, want %q", gotName, name)
				}
				wantQueues := requested
				if existing == 1 {
					wantQueues = 1
				}
				if got := len(tun.QueuesOf(dev)); got != wantQueues {
					t.Errorf("queues = %d, want %d", got, wantQueues)
				}
				for _, q := range tun.QueuesOf(dev) {
					ioctlRecoveryFile(t, q.File(), func(fd int) error {
						ifr, err := unix.NewIfreq(name)
						if err != nil {
							return err
						}
						if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil {
							return err
						}
						if got := ifr.Uint16()&unix.IFF_MULTI_QUEUE != 0; got != (existing > 1) {
							t.Errorf("multiqueue mode = %v, want %v", got, existing > 1)
						}
						return nil
					})
				}
				after, err := net.InterfaceByName(name)
				if err != nil {
					t.Fatal(err)
				}
				if after.Index != before.Index {
					t.Error("interface was recreated")
				}
				if after.Flags&net.FlagUp == 0 {
					t.Error("interface is no longer up")
				}
				addrs, err := after.Addrs()
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, a := range addrs {
					if a.String() == addr.IPNet.String() {
						found = true
					}
				}
				if !found {
					t.Errorf("address lost: %v", addrs)
				}
				routes, err := netlink.RouteListFiltered(unix.AF_INET, route, netlink.RT_FILTER_OIF|netlink.RT_FILTER_DST)
				if err != nil {
					t.Fatal(err)
				}
				if len(routes) != 1 {
					t.Errorf("route lost: %v", routes)
				}
			})
		}
	}
}

func TestNewRefusesBusyTUN(t *testing.T) {
	for _, mode := range []string{"single", "singleNoCarrier", "multi", "disabledOnly"} {
		t.Run(mode, func(t *testing.T) {
			queues := 4
			if mode == "single" || mode == "singleNoCarrier" {
				queues = 1
			}
			old, name := persistentTestTUN(t, queues)
			if mode == "singleNoCarrier" {
				ioctlRecoveryFile(t, old.File(), func(fd int) error {
					return unix.IoctlSetPointerInt(fd, unix.TUNSETCARRIER, 0)
				})
			}
			before, err := net.InterfaceByName(name)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "disabledOnly" {
				for _, q := range tun.QueuesOf(old) {
					ioctlRecoveryFile(t, q.File(), func(fd int) error {
						ifr, err := unix.NewIfreq(name)
						if err != nil {
							return err
						}
						ifr.SetUint16(unix.IFF_DETACH_QUEUE)
						return unix.IoctlIfreq(fd, unix.TUNSETQUEUE, ifr)
					})
				}
			}
			dev, _, err := New(t.Logf, name)
			if dev != nil {
				dev.Close()
				t.Fatal("adopted busy interface")
			}
			if !errors.Is(err, unix.EBUSY) {
				t.Fatalf("error = %v, want EBUSY", err)
			}
			if queues > 1 {
				want := "active=4, disabled=0"
				if mode == "disabledOnly" {
					want = "active=0, disabled=4"
				}
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error missing queue counts %q: %v", want, err)
				}
			}
			after, err := net.InterfaceByName(name)
			if err != nil {
				t.Fatal(err)
			}
			if after.Index != before.Index {
				t.Error("busy interface replaced")
			}
		})
	}
}

func TestNewConcurrentRecovery(t *testing.T) {
	t.Setenv("TS_DEBUG_MAX_QUEUES", "4")
	for _, existing := range []int{1, 4} {
		t.Run(strconv.Itoa(existing), func(t *testing.T) {
			old, name := persistentTestTUN(t, existing)
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			type result struct {
				dev  tun.Device
				name string
				err  error
			}
			start := make(chan struct{})
			results := make(chan result, 2)
			for range 2 {
				go func() {
					<-start
					dev, name, err := New(t.Logf, name)
					results <- result{dev, name, err}
				}()
			}
			close(start)
			succeeded := 0
			for range 2 {
				r := <-results
				if r.err != nil {
					t.Logf("concurrent creation failed: %v", r.err)
					continue
				}
				succeeded++
				// Retain every successful device until both attempts finish.
				t.Cleanup(func() { r.dev.Close() })
				if r.name != name {
					t.Errorf("name = %q, want %q", r.name, name)
				}
				wantQueues := 4
				if existing == 1 {
					wantQueues = 1
				}
				if got := len(tun.QueuesOf(r.dev)); got != wantQueues {
					t.Errorf("queues = %d, want %d", got, wantQueues)
				}
			}
			// Both attempts may fail if their multiqueue attachments overlap.
			if succeeded > 1 {
				t.Fatalf("%d concurrent adopters succeeded, want at most 1", succeeded)
			}
			if _, err := net.InterfaceByName(name); err != nil {
				t.Fatalf("successful creator lost its interface: %v", err)
			}
		})
	}
}

func TestDiagnoseLinuxTUNBusy(t *testing.T) {
	name := recoveryTestName()
	createErr := fmt.Errorf("CreateTUN(%q): unexpected TUN attachments (active=0, disabled=4, owned=0): %w", name, unix.EBUSY)
	var logs []string
	diagnoseLinuxTUNFailure(name, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}, createErr)
	got := strings.Join(logs, "\n")
	if !strings.Contains(got, createErr.Error()) {
		t.Errorf("diagnostic omitted recovery error: %s", got)
	}
	if strings.Contains(got, "lsof") {
		t.Errorf("diagnostic still recommends lsof: %s", got)
	}
}

func TestTUNFDInfoMatches(t *testing.T) {
	for _, tt := range []struct {
		name, data, tunName string
		want                bool
	}{
		{"tun", "pos:\t0\nflags:\t0104002\niff:\ttailscale0\n", "tailscale0", true},
		{"noFinalNewline", "iff: tailscale0", "tailscale0", true},
		{"whitespace", "iff:\t tailscale0 \t\n", "tailscale0", true},
		{"differentInterface", "iff:\ttailscale1\n", "tailscale0", false},
		{"namePrefix", "iff:\ttailscale00\n", "tailscale0", false},
		{"differentField", "notiff:\ttailscale0\n", "tailscale0", false},
		{"otherFD", "pos:\t0\nflags:\t0104002\n", "tailscale0", false},
		{"unattached", "iff:\t\n", "tailscale0", false},
		{"emptyName", "iff:\t\n", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tunFDInfoMatches([]byte(tt.data), tt.tunName); got != tt.want {
				t.Errorf("match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogLinuxTUNHolders(t *testing.T) {
	root := t.TempDir()
	write := func(path, contents string) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("123/comm", "tailscaled\n")
	write("123/fdinfo/4", "pos:\t0\niff:\ttailscale0\n")
	write("123/fdinfo/5", "iff:\ttailscale0\n")
	write("456/comm", "not-a-holder\n")
	write("456/fdinfo/6", "iff:\ttailscale00\n")
	write("456/fdinfo/7", "pos:\t0\n")
	write("789/fdinfo/8", "iff:\ttailscale0\n")  // Process name unavailable.
	write("self/fdinfo/9", "iff:\ttailscale0\n") // Non-PID entry.
	write("999/fdinfo", "not a directory")
	// Process exit can remove fdinfo during a scan.
	if err := os.MkdirAll(filepath.Join(root, "111"), 0700); err != nil {
		t.Fatal(err)
	}

	var logs []string
	logLinuxTUNHolders("tailscale0", root, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	got := strings.Join(logs, "\n")
	for _, want := range []string{
		`TUN holder candidate for "tailscale0": pid=123 comm="tailscaled" fd=4`,
		`TUN holder candidate for "tailscale0": pid=123 comm="tailscaled" fd=5`,
		`TUN holder candidate for "tailscale0": pid=789 comm="unknown" fd=8`,
		"could not read 1 proc entries",
		"names can repeat across network namespaces",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("logs missing %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"pid=456", "pid=self", "No visible process", "lsof"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("logs unexpectedly contain %q:\n%s", unwanted, got)
		}
	}
}

func TestLogLinuxTUNHoldersNoneVisible(t *testing.T) {
	var logs []string
	logLinuxTUNHolders("tailscale0", t.TempDir(), func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	got := strings.Join(logs, "\n")
	for _, want := range []string{"does not prove it is unused", "PID namespace", "/proc/<pid>/fdinfo"} {
		if !strings.Contains(got, want) {
			t.Errorf("logs missing %q:\n%s", want, got)
		}
	}
}

func TestLogLinuxTUNHoldersProcUnavailable(t *testing.T) {
	var logs []string
	logLinuxTUNHolders("tailscale0", filepath.Join(t.TempDir(), "missing"), func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	if len(logs) != 1 || !strings.Contains(logs[0], "Cannot scan") {
		t.Fatalf("unexpected logs: %v", logs)
	}
}

func TestLogLinuxTUNHoldersLive(t *testing.T) {
	for _, mode := range []string{"single", "multi", "disabledOnly"} {
		t.Run(mode, func(t *testing.T) {
			queues := 4
			if mode == "single" {
				queues = 1
			}
			dev, name := persistentTestTUN(t, queues)
			if mode == "disabledOnly" {
				for _, q := range tun.QueuesOf(dev) {
					ioctlRecoveryFile(t, q.File(), func(fd int) error {
						ifr, err := unix.NewIfreq(name)
						if err != nil {
							return err
						}
						ifr.SetUint16(unix.IFF_DETACH_QUEUE)
						return unix.IoctlIfreq(fd, unix.TUNSETQUEUE, ifr)
					})
				}
			}
			var logs []string
			logLinuxTUNHolders(name, "/proc", func(format string, args ...any) {
				logs = append(logs, fmt.Sprintf(format, args...))
			})
			got := strings.Join(logs, "\n")
			want := fmt.Sprintf("TUN holder candidate for %q: pid=%d ", name, os.Getpid())
			if n := strings.Count(got, want); n != queues {
				t.Errorf("found %d fds for this process, want %d:\n%s", n, queues, got)
			}
		})
	}
}
