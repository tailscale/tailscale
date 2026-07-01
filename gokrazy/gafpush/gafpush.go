// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// gafpush pushes a Gokrazy Archive Format (GAF) file to a running
// Tailscale appliance over the network without moving the SD card.
//
// The flow:
//  1. Start a local HTTP server on an ephemeral port, auto-detecting
//     the local IP on the same subnet as the target.
//  2. SSH into the appliance and run: tailscale update --
//     --gokrazy-update-from-url=http://<local>:<port>/file.gaf --unsigned
//  3. The appliance downloads the GAF, writes partitions, switches root,
//     and reboots.
//  4. Wait for the appliance to come back on SSH.
//
// Usage:
//
//	gafpush --gaf=path/to/file.gaf --pi=<ip>
//
// Or via the Makefile:
//
//	make tsapp-push-pi PI=<ip>
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var (
	gafPath = flag.String("gaf", "", "path to the GAF file to push")
	piAddr  = flag.String("pi", "", "IP address of the target Pi")
)

func main() {
	flag.Parse()
	if *gafPath == "" || *piAddr == "" {
		flag.Usage()
		os.Exit(1)
	}

	fi, err := os.Stat(*gafPath)
	if err != nil {
		log.Fatalf("GAF file: %v", err)
	}
	absGAF, _ := filepath.Abs(*gafPath)
	log.Printf("GAF: %s (%.1f MB)", absGAF, float64(fi.Size())/(1<<20))

	localIP, err := findLocalIPFor(*piAddr)
	if err != nil {
		log.Fatalf("finding local IP on same subnet as %s: %v", *piAddr, err)
	}

	// Start HTTP server on an ephemeral port.
	ln, err := net.Listen("tcp", net.JoinHostPort(localIP, "0"))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	gafURL := fmt.Sprintf("http://%s:%s/%s", localIP, port, filepath.Base(absGAF))

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("serving %s to %s", absGAF, r.RemoteAddr)
			http.ServeFile(w, r, absGAF)
		}),
	}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	log.Printf("serving GAF at %s", gafURL)
	log.Printf("SSHing into %s to trigger update...", *piAddr)

	// SSH into the Pi and run tailscale update with the GAF URL.
	cmd := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"root@"+*piAddr,
		"tailscale", "update", "--",
		"--gokrazy-update-from-url="+gafURL,
		"--unsigned",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// The SSH connection may drop when the Pi reboots, which is expected.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 255 {
			log.Printf("SSH connection closed (Pi is rebooting)")
		} else {
			log.Fatalf("ssh: %v", err)
		}
	}

	log.Printf("update pushed; Pi should reboot into the new image shortly")
	log.Printf("waiting for Pi to come back...")
	waitForPi(*piAddr)
}

// findLocalIPFor returns our local IP address that's on the same subnet
// as the given remote IP. It does this by dialing a UDP connection (which
// doesn't actually send anything) and checking the local address chosen.
func findLocalIPFor(remoteIP string) (string, error) {
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(remoteIP, "9"), time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	host, _, _ := net.SplitHostPort(conn.LocalAddr().String())
	return host, nil
}

// waitForPi polls the Pi's SSH port until it comes back up.
func waitForPi(addr string) {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, "22"), 2*time.Second)
		if err == nil {
			conn.Close()
			log.Printf("Pi is back at %s:22", addr)
			return
		}
		time.Sleep(2 * time.Second)
	}
	log.Printf("timed out waiting for Pi to come back (may have gotten a new IP)")
}
