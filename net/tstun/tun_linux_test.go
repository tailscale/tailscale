// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tstun

import (
	"encoding/binary"
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

	"github.com/mdlayher/netlink"
	tnetlink "github.com/tailscale/netlink"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

func TestCreateTUNWithRetry(t *testing.T) {
	uncertain := errors.New("missing attachment counts")
	for _, tt := range []struct {
		name                                       string
		firstErr, secondErr, adoptErr, modprobeErr error
		wantCalls                                  []string
		wantErr                                    error
		noHook                                     bool
	}{
		{name: "created", wantCalls: []string{"create"}},
		{name: "adopted", firstErr: fmt.Errorf("create: %w", unix.EBUSY), wantCalls: []string{"create", "adopt"}},
		{name: "busy", firstErr: unix.EBUSY, adoptErr: unix.EBUSY, wantCalls: []string{"create", "adopt"}, wantErr: unix.EBUSY},
		{name: "uncertain", firstErr: unix.EBUSY, adoptErr: uncertain, wantCalls: []string{"create", "adopt"}, wantErr: uncertain},
		{name: "adoptOtherError", firstErr: unix.EBUSY, adoptErr: unix.EPERM, wantCalls: []string{"create", "adopt"}, wantErr: unix.EPERM},
		{name: "moduleHookUnset", firstErr: unix.ENOENT, noHook: true, wantCalls: []string{"create"}, wantErr: unix.ENOENT},
		{name: "adoptWithoutModuleHook", firstErr: unix.EBUSY, noHook: true, wantCalls: []string{"create", "adopt"}},
		{name: "moduleLoaded", firstErr: unix.ENOENT, wantCalls: []string{"create", "modprobe", "create"}},
		{name: "moduleFailed", firstErr: unix.ENOENT, modprobeErr: unix.EPERM, wantCalls: []string{"create", "modprobe"}, wantErr: unix.ENOENT},
		{name: "moduleRetryFailed", firstErr: unix.ENOENT, secondErr: unix.EBUSY, wantCalls: []string{"create", "modprobe", "create"}, wantErr: unix.EBUSY},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := NewFake()
			defer fake.Close()
			var calls []string
			creates := 0
			modprobe := func() error {
				calls = append(calls, "modprobe")
				return tt.modprobeErr
			}
			if tt.noHook {
				modprobe = nil
			}
			dev, err := createTUNWithRetry(t.Logf, "test0", func() (tun.Device, error) {
				calls = append(calls, "create")
				creates++
				createErr := tt.firstErr
				if creates > 1 {
					createErr = tt.secondErr
				}
				if createErr != nil {
					return nil, createErr
				}
				return fake, nil
			}, func() (tun.Device, error) {
				calls = append(calls, "adopt")
				if tt.adoptErr != nil {
					return nil, tt.adoptErr
				}
				return fake, nil
			}, modprobe)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && dev != fake {
				t.Errorf("device = %v, want fake device", dev)
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

func TestNewCreatesTUN(t *testing.T) {
	t.Cleanup(modprobeTunHook.SetForTest(nil))
	for _, queues := range []int{1, 4} {
		for _, naming := range []string{"literal", "wildcard", "empty"} {
			t.Run(fmt.Sprintf("%d/%s", queues, naming), func(t *testing.T) {
				t.Setenv("TS_DEBUG_MAX_QUEUES", strconv.Itoa(queues))
				name := recoveryTestName()
				if naming == "wildcard" {
					name += "%d"
				}
				if naming == "empty" {
					name = ""
				}
				dev, actual, err := New(t.Logf, name)
				if err != nil {
					if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrNotExist) {
						t.Skipf("needs /dev/net/tun and CAP_NET_ADMIN: %v", err)
					}
					t.Fatal(err)
				}
				t.Cleanup(func() { dev.Close() })
				if actual == "" || strings.Contains(actual, "%") {
					t.Fatalf("unresolved name %q", actual)
				}
				if naming == "literal" && actual != name {
					t.Errorf("name = %q, want %q", actual, name)
				}
				if got := len(tun.QueuesOf(dev)); got != queues {
					t.Errorf("queues = %d, want %d", got, queues)
				}
				wantFlags := tunRequiredFlags | unix.IFF_VNET_HDR
				if queues > 1 {
					wantFlags |= unix.IFF_MULTI_QUEUE
				}
				for _, q := range tun.QueuesOf(dev) {
					ioctlRecoveryFile(t, q.File(), func(fd int) error {
						ifr, err := unix.NewIfreq("")
						if err != nil {
							return err
						}
						if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil {
							return err
						}
						if ifr.Name() != actual {
							t.Errorf("queue name = %q, want %q", ifr.Name(), actual)
						}
						if got := ifr.Uint16() & tunQueueFlagsMask; got != wantFlags {
							t.Errorf("flags = %#x, want %#x", got, wantFlags)
						}
						flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
						if err != nil {
							return err
						}
						if flags&unix.FD_CLOEXEC == 0 {
							t.Error("queue is not close-on-exec")
						}
						flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
						if err != nil {
							return err
						}
						if flags&unix.O_NONBLOCK == 0 {
							t.Error("queue is blocking")
						}
						return nil
					})
				}
				files, err := createTUNFiles(actual, queues)
				for _, f := range files {
					f.Close()
				}
				if !errors.Is(err, unix.EBUSY) {
					t.Fatalf("exclusive creation = %v, want EBUSY", err)
				}
			})
		}
	}
}

func TestCreateTUNFilesInvalidQueues(t *testing.T) {
	for _, queues := range []int{0, -1} {
		if files, err := createTUNFiles(recoveryTestName(), queues); err == nil {
			for _, f := range files {
				f.Close()
			}
			t.Errorf("accepted queue count %d", queues)
		}
	}
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

var recoveryTestSeq atomic.Uint32

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

func persistentTestTUN(t *testing.T, queues int) (tun.Device, string) {
	t.Helper()
	name := recoveryTestName()
	files, err := createTUNFiles(name, queues)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrNotExist) {
			t.Skipf("needs /dev/net/tun and CAP_NET_ADMIN: %v", err)
		}
		t.Fatal(err)
	}
	var fds []int
	defer func() {
		for _, f := range files {
			f.Close()
		}
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	for _, f := range files {
		ioctlRecoveryFile(t, f, func(fd int) error {
			dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
			if err == nil {
				fds = append(fds, dup)
			}
			return err
		})
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
		flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
		if queues > 1 {
			flags |= unix.IFF_MULTI_QUEUE
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
				link, err := tnetlink.LinkByName(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := tnetlink.LinkSetUp(link); err != nil {
					t.Fatal(err)
				}
				addr, err := tnetlink.ParseAddr("198.18.255.254/32")
				if err != nil {
					t.Fatal(err)
				}
				if err := tnetlink.AddrAdd(link, addr); err != nil {
					t.Fatal(err)
				}
				_, dst, err := net.ParseCIDR("198.19.255.254/32")
				if err != nil {
					t.Fatal(err)
				}
				route := &tnetlink.Route{LinkIndex: before.Index, Dst: dst, Scope: tnetlink.SCOPE_LINK}
				if err := tnetlink.RouteAdd(route); err != nil {
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
				routes, err := tnetlink.RouteListFiltered(unix.AF_INET, route, tnetlink.RT_FILTER_OIF|tnetlink.RT_FILTER_DST)
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

func TestAdoptTUNVnetHeader(t *testing.T) {
	for _, queues := range []int{1, 4} {
		for _, mode := range []string{"largeHeader", "foreignByteOrder", "nativeByteOrder"} {
			t.Run(fmt.Sprintf("%d/%s", queues, mode), func(t *testing.T) {
				old, name := persistentTestTUN(t, queues)
				before, err := net.InterfaceByName(name)
				if err != nil {
					t.Fatal(err)
				}
				request, value := uint(unix.TUNSETVNETHDRSZ), 12
				if mode != "largeHeader" {
					little := binary.NativeEndian.Uint16([]byte{1, 0}) == 1
					if mode == "foreignByteOrder" {
						little = !little
					}
					request, value = unix.TUNSETVNETBE, 1
					if little {
						request = unix.TUNSETVNETLE
					}
				}
				var configErr error
				ioctlRecoveryFile(t, old.File(), func(fd int) error {
					configErr = unix.IoctlSetPointerInt(fd, request, value)
					return nil
				})
				if configErr != nil {
					if errors.Is(configErr, unix.EINVAL) || errors.Is(configErr, unix.ENOTTY) {
						t.Skipf("kernel does not support this virtio header setting: %v", configErr)
					}
					t.Fatal(configErr)
				}
				if err := old.Close(); err != nil {
					t.Fatal(err)
				}
				dev, err := adoptTUN(name, 1280, queues)
				if mode == "nativeByteOrder" {
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { dev.Close() })
				} else {
					if dev != nil {
						dev.Close()
						t.Fatal("adopted incompatible virtio header")
					}
					want := "header size 12"
					if mode == "foreignByteOrder" {
						want = "non-native byte order"
					}
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("error = %v, want %q", err, want)
					}
				}
				after, err := net.InterfaceByName(name)
				if err != nil {
					t.Fatal(err)
				}
				if after.Index != before.Index {
					t.Error("interface was recreated")
				}
			})
		}
	}
}

func TestAdoptTUNWithoutVnetHeader(t *testing.T) {
	for _, queues := range []int{1, 4} {
		t.Run(strconv.Itoa(queues), func(t *testing.T) {
			old, name := persistentTestTUN(t, queues)
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			flags := tunRequiredFlags
			if queues > 1 {
				flags |= unix.IFF_MULTI_QUEUE
			}
			f, _, err := openTUNQueue(name, flags)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			dev, err := adoptTUN(name, 1280, queues)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { dev.Close() })
			if dev.BatchSize() != 1 {
				t.Errorf("batch size = %d, want 1", dev.BatchSize())
			}
		})
	}
}

func TestAdoptTUNInitializationFailure(t *testing.T) {
	for _, queues := range []int{1, 4} {
		t.Run(strconv.Itoa(queues), func(t *testing.T) {
			old, name := persistentTestTUN(t, queues)
			before, err := net.InterfaceByName(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			dev, err := adoptTUN(name, 1, queues) // Invalid MTU makes initialization fail.
			if dev != nil {
				dev.Close()
				t.Fatal("adoption with invalid MTU succeeded")
			}
			if err == nil {
				t.Fatal("adoption returned no error")
			}
			after, err := net.InterfaceByName(name)
			if err != nil {
				t.Fatal(err)
			}
			if after.Index != before.Index {
				t.Error("interface was recreated on failure")
			}
			// Initialization failure must release the acquired queues.
			dev, err = adoptTUN(name, 1280, queues)
			if err != nil {
				t.Fatalf("adoption after failure: %v", err)
			}
			t.Cleanup(func() { dev.Close() })
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

func tunTestU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func tunTestAttrs(attrs ...netlink.Attribute) []byte {
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		panic(err)
	}
	return b
}

func tunTestLink(name, kind string, fields map[uint16][]byte) []byte {
	var attrs []netlink.Attribute
	for typ, data := range fields {
		attrs = append(attrs, netlink.Attribute{Type: typ, Data: data})
	}
	data := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(data[4:], 7)
	return append(data, tunTestAttrs(
		netlink.Attribute{Type: unix.IFLA_IFNAME, Data: append([]byte(name), 0)},
		netlink.Attribute{Type: unix.IFLA_LINKINFO | netlink.Nested, Data: tunTestAttrs(
			netlink.Attribute{Type: unix.IFLA_INFO_KIND, Data: append([]byte(kind), 0)},
			netlink.Attribute{Type: unix.IFLA_INFO_DATA | netlink.Nested, Data: tunTestAttrs(attrs...)},
		)},
	)...)
}

func baseTUNTestFields() map[uint16][]byte {
	return map[uint16][]byte{
		unix.IFLA_TUN_TYPE:        {unix.IFF_TUN},
		unix.IFLA_TUN_MULTI_QUEUE: {0},
		unix.IFLA_TUN_PI:          {0},
		unix.IFLA_TUN_VNET_HDR:    {1},
	}
}

func TestParseTUNLink(t *testing.T) {
	baseFlags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	for _, tt := range []struct {
		name    string
		change  func(map[uint16][]byte)
		want    tunLink
		wantErr bool
	}{
		{name: "single", want: tunLink{index: 7, flags: baseFlags}},
		{name: "noVnetHdr", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_VNET_HDR] = []byte{0} }, want: tunLink{index: 7, flags: baseFlags &^ unix.IFF_VNET_HDR}},
		{name: "multi", change: func(a map[uint16][]byte) {
			a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{1}
			a[unix.IFLA_TUN_NUM_QUEUES] = tunTestU32(0)
			a[unix.IFLA_TUN_NUM_DISABLED_QUEUES] = tunTestU32(0)
		}, want: tunLink{index: 7, flags: baseFlags | unix.IFF_MULTI_QUEUE}},
		{name: "holders", change: func(a map[uint16][]byte) {
			a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{1}
			a[unix.IFLA_TUN_NUM_QUEUES] = tunTestU32(2)
			a[unix.IFLA_TUN_NUM_DISABLED_QUEUES] = tunTestU32(3)
		}, want: tunLink{index: 7, flags: baseFlags | unix.IFF_MULTI_QUEUE, queues: 2, disabledQueues: 3}},
		{name: "missingCounts", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{1} }, wantErr: true},
		{name: "missingDisabledCount", change: func(a map[uint16][]byte) {
			a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{1}
			a[unix.IFLA_TUN_NUM_QUEUES] = tunTestU32(0)
		}, wantErr: true},
		{name: "missingActiveCount", change: func(a map[uint16][]byte) {
			a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{1}
			a[unix.IFLA_TUN_NUM_DISABLED_QUEUES] = tunTestU32(0)
		}, wantErr: true},
		{name: "missingMode", change: func(a map[uint16][]byte) { delete(a, unix.IFLA_TUN_MULTI_QUEUE) }, wantErr: true},
		{name: "invalidMode", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{2} }, wantErr: true},
		{name: "tap", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_TYPE] = []byte{unix.IFF_TAP} }, wantErr: true},
		{name: "missingType", change: func(a map[uint16][]byte) { delete(a, unix.IFLA_TUN_TYPE) }, wantErr: true},
		{name: "shortCount", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_NUM_QUEUES] = []byte{0} }, wantErr: true},
		{name: "invalidPI", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_PI] = []byte{2} }, wantErr: true},
		{name: "missingPI", change: func(a map[uint16][]byte) { delete(a, unix.IFLA_TUN_PI) }, wantErr: true},
		{name: "missingVnetHdr", change: func(a map[uint16][]byte) { delete(a, unix.IFLA_TUN_VNET_HDR) }, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			attrs := baseTUNTestFields()
			if tt.change != nil {
				tt.change(attrs)
			}
			got, err := parseTUNLink(tunTestLink("test0", "tun", attrs), "test0")
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
	for _, data := range [][]byte{
		{0},
		make([]byte, unix.SizeofIfInfomsg),
		tunTestLink("test0", "dummy", nil),
		tunTestLink("other0", "tun", nil),
	} {
		if _, err := parseTUNLink(data, "test0"); err == nil {
			t.Errorf("accepted invalid link %x", data)
		}
	}
}

func TestTUNLinkRepeatedPadding(t *testing.T) {
	msg := tunTestLink("test0", "tun", baseTUNTestFields())
	msg = append(msg, tunTestAttrs(
		netlink.Attribute{Type: unix.IFLA_PAD},
		netlink.Attribute{Type: unix.IFLA_PAD},
	)...)
	if _, err := parseTUNLink(msg, "test0"); err != nil {
		t.Fatal(err)
	}
	msg = append(msg, tunTestAttrs(netlink.Attribute{Type: unix.IFLA_IFNAME, Data: []byte("test0\x00")})...)
	if _, err := parseTUNLink(msg, "test0"); err == nil {
		t.Fatal("accepted duplicate interface name")
	}
}

func TestTUNAttrs(t *testing.T) {
	data := tunTestAttrs(netlink.Attribute{Type: unix.IFLA_TUN_NUM_QUEUES, Data: tunTestU32(0)}, netlink.Attribute{Type: unix.IFLA_TUN_NUM_QUEUES, Data: tunTestU32(1)})
	if _, err := tunAttrs(data, unix.IFLA_TUN_NUM_QUEUES); err == nil {
		t.Fatal("accepted duplicate attachment count")
	}
	// Unrequested attributes may repeat.
	if _, err := tunAttrs(data, unix.IFLA_TUN_TYPE); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{{1}, {3, 0, 1, 0}, {8, 0, 1, 0}} {
		if _, err := tunAttrs(data, unix.IFLA_TUN_TYPE); err == nil {
			t.Errorf("accepted malformed attributes %x", data)
		}
	}
}

func TestTUNLinkQueueOwnership(t *testing.T) {
	for _, tt := range []struct {
		active, disabled, owned uint32
		wantErr                 bool
	}{
		{0, 0, 0, false}, {1, 0, 1, false}, {4, 0, 4, false},
		{1, 0, 0, true}, {0, 1, 0, true}, {2, 0, 1, true}, {1, 1, 1, true},
	} {
		link := tunLink{flags: unix.IFF_MULTI_QUEUE, queues: tt.active, disabledQueues: tt.disabled}
		err := link.checkQueues(tt.owned)
		if errors.Is(err, unix.EBUSY) != tt.wantErr {
			t.Errorf("%+v owned=%d: %v", link, tt.owned, err)
		}
	}
}

func FuzzParseTUNLink(f *testing.F) {
	f.Add(tunTestLink("test0", "tun", baseTUNTestFields()))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseTUNLink(data, "test0") })
}

func TestAdoptTUNRefusesNonTUN(t *testing.T) {
	dev, err := adoptTUN("lo", 1280, 1)
	if dev != nil {
		dev.Close()
		t.Fatal("adopted loopback interface")
	}
	if err == nil {
		t.Fatal("accepted loopback interface")
	}
}

func TestAdoptTUNMissing(t *testing.T) {
	if _, err := adoptTUN(recoveryTestName(), 1280, 1); !errors.Is(err, unix.ENODEV) {
		t.Fatalf("got %v, want ENODEV", err)
	}
}

func TestAdoptTUNErrorPrefix(t *testing.T) {
	for _, name := range []string{"", "name-too-long-for-tun", "bad\x00name", recoveryTestName(), "lo"} {
		_, err := adoptTUN(name, 1280, 1)
		if err == nil {
			t.Fatalf("adoptTUN(%q) unexpectedly succeeded", name)
		}
		if msg := err.Error(); !strings.HasPrefix(msg, "adoptTUN: ") || strings.Count(msg, "adoptTUN: ") != 1 {
			t.Errorf("error must have exactly one adoptTUN prefix: %v", err)
		}
	}
}
func TestDiagnoseLinuxTUNBusy(t *testing.T) {
	name := recoveryTestName()
	createErr := fmt.Errorf("createTUN: adopt %q: adoptTUN: unexpected TUN attachments (active=0, disabled=4, owned=0): %w", name, unix.EBUSY)
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
