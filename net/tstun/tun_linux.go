// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tstun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

func createTUN(logf logger.Logf, name string, mtu, queues int) (tun.Device, error) {
	return createTUNWithRetry(logf, name, func() (tun.Device, error) {
		return tun.CreateTUN(name, mtu, tun.WithQueues(queues))
	}, func() (tun.Device, error) {
		return adoptTUN(name, mtu, queues)
	}, modprobeTunHook.GetOrNil())
}

func createTUNWithRetry(logf logger.Logf, name string, create, adopt func() (tun.Device, error), modprobe func() error) (tun.Device, error) {
	dev, err := create()
	if err == nil {
		return dev, nil
	}
	if errors.Is(err, unix.EBUSY) {
		dev, err := adopt()
		if err != nil {
			return nil, fmt.Errorf("createTUN: adopt %q: %w", name, err)
		}
		logf("adopted unattached TUN interface %q", name)
		return dev, nil
	}

	return retryTUNAfterModprobe(logf, name, create, err, modprobe)
}

// adoptTUN attaches to an existing TUN interface and preserves its queue mode.
// It uses one queue for a single-queue interface, regardless of queues.
// Multiqueue attachment checks do not prevent concurrent attachments.
func adoptTUN(name string, mtu, queues int) (_ tun.Device, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("adoptTUN: %w", err)
		}
	}()
	if name == "" || len(name) >= unix.IFNAMSIZ || strings.IndexByte(name, 0) >= 0 {
		return nil, fmt.Errorf("invalid TUN name %q", name)
	}
	if queues < 1 {
		return nil, fmt.Errorf("invalid queue count %d", queues)
	}
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	link, err := queryTUNLink(conn, name)
	if err != nil {
		return nil, err
	}
	if link.flags&unix.IFF_NO_PI == 0 {
		return nil, fmt.Errorf("TUN %q uses an unsupported packet information header", name)
	}
	if err := link.checkQueues(0); err != nil {
		return nil, err
	}

	first, err := attachTUNQueue(name, link.flags)
	if err != nil {
		return nil, err
	}
	files := []*os.File{first}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	check := func() error {
		current, err := queryTUNLink(conn, name)
		if err != nil {
			return err
		}
		if current.index != link.index || current.flags != link.flags {
			return fmt.Errorf("TUN %q changed during adoption", name)
		}
		return current.checkQueues(uint32(len(files)))
	}
	// TUNSETIFF can create an interface if the queried one has disappeared.
	if err := check(); err != nil {
		return nil, err
	}
	if link.flags&unix.IFF_MULTI_QUEUE != 0 {
		for len(files) < queues {
			f, err := attachTUNQueue(name, link.flags)
			if err != nil {
				break // Use the queues already opened.
			}
			files = append(files, f)
		}
		if err := check(); err != nil {
			return nil, err
		}
	}
	// tun.CreateTUNFromFiles takes ownership even on error.
	owned := files
	files = nil
	return tun.CreateTUNFromFiles(owned, mtu)
}

func attachTUNQueue(name string, flags uint16) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err == nil {
		ifr.SetUint16(flags)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

type tunLink struct {
	index                  uint32
	flags                  uint16
	queues, disabledQueues uint32
}

func (link tunLink) checkQueues(owned uint32) error {
	if link.flags&unix.IFF_MULTI_QUEUE != 0 && (link.queues != owned || link.disabledQueues != 0) {
		return fmt.Errorf("unexpected TUN attachments (active=%d, disabled=%d, owned=%d): %w", link.queues, link.disabledQueues, owned, unix.EBUSY)
	}
	return nil
}

func queryTUNLink(conn *netlink.Conn, name string) (tunLink, error) {
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.IFLA_IFNAME, Data: append([]byte(name), 0)}})
	if err != nil {
		return tunLink{}, err
	}
	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_GETLINK, Flags: netlink.Request},
		Data:   append(make([]byte, unix.SizeofIfInfomsg), attrs...),
	})
	if err != nil {
		return tunLink{}, err
	}
	if len(msgs) != 1 || msgs[0].Header.Type != unix.RTM_NEWLINK || msgs[0].Header.Flags&netlink.Multi != 0 {
		return tunLink{}, fmt.Errorf("unexpected RTM_GETLINK response")
	}
	return parseTUNLink(msgs[0].Data, name)
}

func parseTUNLink(data []byte, name string) (tunLink, error) {
	var link tunLink
	if len(data) < unix.SizeofIfInfomsg {
		return link, fmt.Errorf("short link message")
	}
	link.index = binary.NativeEndian.Uint32(data[4:])
	attrs, err := tunAttrs(data[unix.SizeofIfInfomsg:], unix.IFLA_IFNAME, unix.IFLA_LINKINFO)
	if err != nil {
		return link, err
	}
	if int32(link.index) <= 0 || !bytes.Equal(attrs[unix.IFLA_IFNAME], append([]byte(name), 0)) {
		return link, fmt.Errorf("unexpected link identity")
	}
	info, err := tunAttrs(attrs[unix.IFLA_LINKINFO], unix.IFLA_INFO_KIND, unix.IFLA_INFO_DATA)
	if err != nil {
		return link, err
	}
	if !bytes.Equal(info[unix.IFLA_INFO_KIND], []byte("tun\x00")) {
		return link, fmt.Errorf("interface is not a TUN")
	}
	attrs, err = tunAttrs(info[unix.IFLA_INFO_DATA], unix.IFLA_TUN_TYPE, unix.IFLA_TUN_MULTI_QUEUE, unix.IFLA_TUN_PI, unix.IFLA_TUN_VNET_HDR, unix.IFLA_TUN_NUM_QUEUES, unix.IFLA_TUN_NUM_DISABLED_QUEUES)
	if err != nil {
		return link, err
	}
	if typ := attrs[unix.IFLA_TUN_TYPE]; len(typ) != 1 || typ[0] != unix.IFF_TUN {
		return link, fmt.Errorf("interface is not a TUN")
	}
	link.flags = unix.IFF_TUN
	for _, field := range []struct {
		attr     uint16
		flag     uint16
		inverted bool
	}{
		{unix.IFLA_TUN_MULTI_QUEUE, unix.IFF_MULTI_QUEUE, false},
		{unix.IFLA_TUN_PI, unix.IFF_NO_PI, true},
		{unix.IFLA_TUN_VNET_HDR, unix.IFF_VNET_HDR, false},
	} {
		v := attrs[field.attr]
		if len(v) != 1 || v[0] > 1 {
			return link, fmt.Errorf("missing or invalid TUN flag %d", field.attr)
		}
		if (v[0] != 0) != field.inverted {
			link.flags |= field.flag
		}
	}
	for _, field := range []struct {
		attr  uint16
		value *uint32
	}{
		{unix.IFLA_TUN_NUM_QUEUES, &link.queues},
		{unix.IFLA_TUN_NUM_DISABLED_QUEUES, &link.disabledQueues},
	} {
		v, present := attrs[field.attr]
		if !present && link.flags&unix.IFF_MULTI_QUEUE == 0 {
			continue
		}
		if len(v) != 4 {
			return link, fmt.Errorf("missing or invalid TUN queue count %d", field.attr)
		}
		*field.value = binary.NativeEndian.Uint32(v)
	}
	return link, nil
}

// tunAttrs returns the requested attributes, rejecting duplicate occurrences.
func tunAttrs(data []byte, fields ...uint16) (map[uint16][]byte, error) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return nil, err
	}
	attrs := make(map[uint16][]byte)
	for ad.Next() {
		typ := ad.Type()
		if !slices.Contains(fields, typ) {
			continue
		}
		if _, present := attrs[typ]; present {
			return nil, fmt.Errorf("duplicate netlink attribute %d", typ)
		}
		attrs[typ] = ad.Bytes()
	}
	return attrs, ad.Err()
}

func init() {
	tunDiagnoseFailure = diagnoseLinuxTUNFailure
	modprobeTunHook.Set(func() error {
		_, err := modprobeTun()
		return err
	})
}

func modprobeTun() ([]byte, error) {
	return exec.Command("/sbin/modprobe", "tun").CombinedOutput()
}

func diagnoseLinuxTUNFailure(tunName string, logf logger.Logf, createErr error) {
	if errors.Is(createErr, syscall.EBUSY) {
		logf("TUN device %q already exists or has attached queues; automatic recovery failed: %v", tunName, createErr)
		logLinuxTUNHolders(tunName, "/proc", logf)
		logf("Verify any candidate holders before stopping a conflicting Tailscale instance and retrying")
		return
	}

	var un syscall.Utsname
	err := syscall.Uname(&un)
	if err != nil {
		logf("no TUN, and failed to look up kernel version: %v", err)
		return
	}
	kernel := utsReleaseField(&un)
	logf("Linux kernel version: %s", kernel)

	modprobeOut, err := modprobeTun()
	if err == nil {
		logf("'modprobe tun' successful")
		// Either tun is currently loaded, or it's statically
		// compiled into the kernel (which modprobe checks
		// with /lib/modules/$(uname -r)/modules.builtin)
		//
		// So if there's a problem at this point, it's
		// probably because /dev/net/tun doesn't exist.
		const dev = "/dev/net/tun"
		if fi, err := os.Stat(dev); err != nil {
			logf("tun module loaded in kernel, but %s does not exist", dev)
		} else {
			logf("%s: %v", dev, fi.Mode())
		}

		// We failed to find why it failed. Just let our
		// caller report the error it got from wireguard-go.
		return
	}
	logf("is CONFIG_TUN enabled in your kernel? `modprobe tun` failed with: %s", modprobeOut)

	switch distro.Get() {
	case distro.Debian:
		dpkgOut, err := exec.Command("dpkg", "-S", "kernel/drivers/net/tun.ko").CombinedOutput()
		if len(bytes.TrimSpace(dpkgOut)) == 0 || err != nil {
			logf("tun module not loaded nor found on disk")
			return
		}
		if !bytes.Contains(dpkgOut, []byte(kernel)) {
			logf("kernel/drivers/net/tun.ko found on disk, but not for current kernel; are you in middle of a system update and haven't rebooted? found: %s", dpkgOut)
		}
	case distro.Arch:
		findOut, err := exec.Command("find", "/lib/modules/", "-path", "*/net/tun.ko*").CombinedOutput()
		if len(bytes.TrimSpace(findOut)) == 0 || err != nil {
			logf("tun module not loaded nor found on disk")
			return
		}
		if !bytes.Contains(findOut, []byte(kernel)) {
			logf("kernel/drivers/net/tun.ko found on disk, but not for current kernel; are you in middle of a system update and haven't rebooted? found: %s", findOut)
		}
	case distro.OpenWrt:
		// OpenWRT switched to using apk as a package manager as of OpenWrt 25.12.0.
		// Find out what is used on this system and use that, Maybe we can get rid
		// of opkg in the future but for now keep checking.

		if path, err := exec.LookPath("apk"); err == nil && path != "" {
			// Test with apk
			out, err := exec.Command("apk", "info").CombinedOutput()
			if err != nil {
				logf("error querying OpenWrt installed packages with apk: %s", out)
				return
			}
			for _, pkg := range []string{"kmod-tun", "ca-bundle"} {
				if !bytes.Contains(out, []byte(pkg)) {
					logf("Missing required package %s; run: apk add %s", pkg, pkg)
				}
			}
		} else { // Check for package with opkg (legacy)
			out, err := exec.Command("opkg", "list-installed").CombinedOutput()
			if err != nil {
				logf("error querying OpenWrt installed packages with opkg: %s", out)
				return
			}
			for _, pkg := range []string{"kmod-tun", "ca-bundle"} {
				if !bytes.Contains(out, []byte(pkg+" - ")) {
					logf("Missing required package %s; run: opkg install %s", pkg, pkg)
				}
			}
		}
	}
}

// logLinuxTUNHolders reports processes with an fdinfo iff field matching tunName.
// Interface names may repeat across network namespaces.
func logLinuxTUNHolders(tunName, procRoot string, logf logger.Logf) {
	processes, err := os.ReadDir(procRoot)
	if err != nil {
		logf("Cannot scan %s for TUN holders: %v", procRoot, err)
		return
	}
	matches, unreadable := 0, 0
	for _, process := range processes {
		pid := process.Name()
		if n, err := strconv.Atoi(pid); err != nil || n <= 0 {
			continue
		}
		pidDir := filepath.Join(procRoot, pid)
		fds, err := os.ReadDir(filepath.Join(pidDir, "fdinfo"))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				unreadable++
			}
			continue
		}
		for _, fd := range fds {
			if n, err := strconv.Atoi(fd.Name()); err != nil || n < 0 {
				continue
			}
			data, err := os.ReadFile(filepath.Join(pidDir, "fdinfo", fd.Name()))
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					unreadable++
				}
				continue
			}
			if !tunFDInfoMatches(data, tunName) {
				continue
			}
			comm := "unknown"
			if data, err := os.ReadFile(filepath.Join(pidDir, "comm")); err == nil {
				comm = strings.TrimSuffix(string(data), "\n")
			}
			logf("TUN holder candidate for %q: pid=%s comm=%q fd=%s", tunName, pid, comm, fd.Name())
			matches++
		}
	}
	if unreadable != 0 {
		logf("TUN holder scan could not read %d proc entries due to permissions or other errors", unreadable)
	}
	if matches == 0 {
		logf("No visible process fdinfo entries name TUN device %q; this does not prove it is unused", tunName)
		logf("Holders may be inaccessible, outside this PID namespace, or retained by kernel references; inspect from the host with access to /proc/<pid>/fdinfo")
	} else {
		logf("TUN holder candidates match by interface name; names can repeat across network namespaces")
	}
}

func tunFDInfoMatches(data []byte, tunName string) bool {
	if tunName == "" {
		return false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && key == "iff" && strings.TrimSpace(value) == tunName {
			return true
		}
	}
	return false
}

func utsReleaseField(u *syscall.Utsname) string {
	var sb strings.Builder
	for _, v := range u.Release {
		if v == 0 {
			break
		}
		sb.WriteByte(byte(v))
	}
	return strings.TrimSpace(sb.String())
}
