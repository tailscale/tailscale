// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

// The tsshd binary is an SSH server that accepts connections
// from anybody on the same Tailscale network.
//
// It does not use passwords or SSH public key.
//
// Any user name is accepted; users are logged in as whoever is
// running this daemon.
//
// Warning: use at your own risk. This code has had very few eyeballs
// on it.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"github.com/gliderlabs/ssh"
	"github.com/kr/pty"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/interfaces"
)

var (
	port    = flag.Int("port", 2200, "port to listen on")
	hostKey = flag.String("hostkey", "", "SSH host key")
)

func main() {
	flag.Parse()
	if *hostKey == "" {
		log.Fatalf("missing required --hostkey")
	}
	hostKey, err := ioutil.ReadFile(*hostKey)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := gossh.ParsePrivateKey(hostKey)
	if err != nil {
		log.Printf("failed to parse SSH host key: %v", err)
		return
	}

	warned := false
	for {
		addr, iface, err := interfaces.Tailscale()
		if err != nil {
			log.Fatalf("listing interfaces: %v", err)
		}
		if addr == nil {
			if !warned {
				log.Printf("no tailscale interface found; polling until one is available")
				warned = true
			}
			// TODO: use netlink or other OS-specific mechanism to efficiently
			// wait for change in interfaces. Polling every N seconds is good enough
			// for now.
			time.Sleep(5 * time.Second)
			continue
		}
		warned = false
		listen := net.JoinHostPort(addr.String(), fmt.Sprint(*port))
		log.Printf("tailscale ssh server listening on %v, %v", iface.Name, listen)
		s := &ssh.Server{
			Addr:    listen,
			Handler: handleSSH,
		}
		s.AddHostKey(signer)

		err = s.ListenAndServe()
		log.Fatalf("tailscale sshd failed: %v", err)
	}

}

func handleSSH(s ssh.Session) {
	user := s.User()
	addr := s.RemoteAddr()
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		log.Printf("tsshd: rejecting non-TCP addr %T %v", addr, addr)
		s.Exit(1)
		return
	}
	if !interfaces.IsTailscaleIP(ta.IP) {
		log.Printf("tsshd: rejecting non-Tailscale addr %v", ta.IP)
		s.Exit(1)
		return
	}

	log.Printf("new session for %q from %v", user, ta)
	defer log.Printf("closing session for %q from %v", user, ta)
	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		fmt.Fprintf(s, "TODO scp etc")
		s.Exit(1)
		return
	}

	userWantsShell := len(s.Command()) == 0

	if userWantsShell {
		shell, err := shellOfUser(s.User())
		if err != nil {
			fmt.Fprintf(s, "failed to find shell: %v\n", err)
			s.Exit(1)
			return
		}
		cmd := exec.Command(shell)
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		f, err := pty.Start(cmd)
		if err != nil {
			log.Printf("running shell: %v", err)
			s.Exit(1)
			return
		}
		defer f.Close()
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			io.Copy(f, s) // stdin
		}()
		io.Copy(s, f) // stdout
		cmd.Process.Kill()
		if err := cmd.Wait(); err != nil {
			s.Exit(1)
		}
		s.Exit(0)
		return
	}

	fmt.Fprintf(s, "TODO: args\n")
	s.Exit(1)
}

func shellOfUser(user string) (string, error) {
	// TODO
	return "/bin/bash", nil
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}
