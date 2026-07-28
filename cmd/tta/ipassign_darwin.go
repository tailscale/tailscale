// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"tailscale.com/tstest/natlab/vnet"
)

const (
	afVSOCK       = 40    // AF_VSOCK on macOS
	vmaddrCIDHost = 2     // VMADDR_CID_HOST
	vsockPort     = 51011 // port for IP assignment protocol
)

// sockaddrVM is the Go equivalent of struct sockaddr_vm from <sys/vsock.h>.
type sockaddrVM struct {
	Len       uint8
	Family    uint8
	Reserved1 uint16
	Port      uint32
	CID       uint32
}

type netConfig struct {
	IP   string `json:"ip"`
	Mask string `json:"mask"`
	GW   string `json:"gw"`
}

// startIPAssignLoop starts a background goroutine that polls the host
// via the virtio socket for an IP assignment. When the host responds
// with a JSON config (rather than "wait"), TTA sets the IP statically
// using ifconfig and stops polling.
func startIPAssignLoop() {
	go ipAssignLoop()
}

func ipAssignLoop() {
	log.Printf("ipassign: starting vsock poll loop")
	var lastErr string
	for attempt := 0; ; attempt++ {
		resp, err := askHostForIP()
		if err != nil {
			if e := err.Error(); e != lastErr {
				log.Printf("ipassign: attempt %d: %v", attempt, err)
				lastErr = e
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if resp == "wait" {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var nc netConfig
		if err := json.Unmarshal([]byte(resp), &nc); err != nil {
			log.Printf("ipassign: bad config: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if err := setStaticIP(nc); err != nil {
			log.Printf("ipassign: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		log.Printf("ipassign: configured en0 with %s/%s gw %s", nc.IP, nc.Mask, nc.GW)

		// Switch the driver address from the DNS name to the IP directly
		// (avoids DNS resolution delay) and kick the dial-out loop so it
		// retries immediately with the new address.
		ipAddr := net.JoinHostPort(vnet.TestDriverIPv4().String(), strconv.Itoa(vnet.TestDriverPort))
		*driverAddr = ipAddr
		log.Printf("ipassign: switched driver addr to %s", ipAddr)
		resetDialCancels()
		return
	}
}

// askHostForIP connects to the host via AF_VSOCK and reads the response.
func askHostForIP() (string, error) {
	fd, err := unix.Socket(afVSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return "", fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)

	// Set a short connect+read timeout via SO_RCVTIMEO.
	tv := unix.Timeval{Sec: 1}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	addr := sockaddrVM{
		Len:    uint8(unsafe.Sizeof(sockaddrVM{})),
		Family: afVSOCK,
		Port:   vsockPort,
		CID:    vmaddrCIDHost,
	}
	_, _, errno := unix.RawSyscall(unix.SYS_CONNECT, uintptr(fd),
		uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr))
	if errno != 0 {
		return "", fmt.Errorf("connect: %w", errno)
	}

	var buf [1024]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	return string(buf[:n]), nil
}

// setStaticIP configures en0 with a static IP address and default route.
func setStaticIP(nc netConfig) error {
	out, err := exec.Command("ifconfig", "en0", nc.IP, "netmask", nc.Mask, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig: %v: %s", err, out)
	}
	out, err = exec.Command("route", "add", "default", nc.GW).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add: %v: %s", err, out)
	}
	return nil
}
