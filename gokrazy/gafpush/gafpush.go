// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// gafpush pushes a Gokrazy Archive Format (GAF) file to a running
// Tailscale appliance over the network without moving the SD card.
//
// The flow:
//  1. scp the GAF to /perm/gafpush.tmp on the appliance (via
//     breakglass's SFTP subsystem).
//  2. SSH into the appliance and run
//     tailscale update -- --gokrazy-update-from-url=file:///perm/gafpush.tmp --unsigned
//     which copies the file into a tmp GAF, writes partitions, switches
//     root, and reboots.
//  3. Wait for the appliance to come back on SSH; then remove
//     /perm/gafpush.tmp.
//
// This flow is purely one-directional (developer → appliance), so
// gafpush works from behind NAT, laptop firewalls (e.g. NixOS's default
// deny-inbound), or when the appliance is on a different subnet.
//
// Usage:
//
//	gafpush --gaf=path/to/file.gaf --host=<ip-or-name>
//
// Or via the Makefile:
//
//	make tsapp-push-pi PI=<ip>
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var (
	gafPath    = flag.String("gaf", "", "path to the GAF file to push")
	host       = flag.String("host", "", "target hostname or IP (SSH as root)")
	piAddr     = flag.String("pi", "", "alias for --host, kept for backwards compatibility with the Makefile")
	remotePath = flag.String("remote-path", "/perm/gafpush.tmp", "where on the appliance to stage the GAF before the update")
)

func main() {
	flag.Parse()
	target := *host
	if target == "" {
		target = *piAddr
	}
	if *gafPath == "" || target == "" {
		flag.Usage()
		os.Exit(1)
	}

	fi, err := os.Stat(*gafPath)
	if err != nil {
		log.Fatalf("GAF file: %v", err)
	}
	absGAF, _ := filepath.Abs(*gafPath)
	log.Printf("GAF: %s (%.1f MB)", absGAF, float64(fi.Size())/(1<<20))

	log.Printf("scp'ing GAF to %s:%s ...", target, *remotePath)
	scp := exec.Command("scp",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		absGAF, "root@"+target+":"+*remotePath,
	)
	scp.Stdout = os.Stdout
	scp.Stderr = os.Stderr
	if err := scp.Run(); err != nil {
		log.Fatalf("scp: %v", err)
	}

	log.Printf("SSHing into %s to trigger update...", target)
	fileURL := "file://" + *remotePath
	sshUpdate := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"root@"+target,
		"tailscale", "update", "--",
		"--gokrazy-update-from-url="+fileURL,
		"--unsigned",
	)
	sshUpdate.Stdout = os.Stdout
	sshUpdate.Stderr = os.Stderr
	if err := sshUpdate.Run(); err != nil {
		// SSH will drop when the appliance reboots, which is expected.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 255 {
			log.Printf("SSH connection closed (appliance is rebooting)")
		} else {
			log.Fatalf("ssh: %v", err)
		}
	}

	log.Printf("update pushed; waiting for %s to come back...", target)
	if !waitForHost(target) {
		log.Printf("timed out waiting for appliance to come back (may have gotten a new IP); leaving %s in place", *remotePath)
		return
	}

	log.Printf("cleaning up staged GAF on %s ...", target)
	sshRm := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"root@"+target,
		"rm", "-f", *remotePath,
	)
	sshRm.Stdout = os.Stdout
	sshRm.Stderr = os.Stderr
	if err := sshRm.Run(); err != nil {
		log.Printf("cleanup: %v (staged GAF still at %s)", err, *remotePath)
	}
}

// waitForHost polls the appliance's SSH port until it comes back up.
// Returns true if it comes back within the deadline.
func waitForHost(addr string) bool {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, "22"), 2*time.Second)
		if err == nil {
			conn.Close()
			log.Printf("appliance is back at %s:22", addr)
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}
