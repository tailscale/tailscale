// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package netstack

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"inet.af/netaddr"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
)

func init() {
	sshDemo = sshDemoImpl
}

func sshDemoImpl(ns *Impl, c net.Conn) error {
	hostKey, err := ioutil.ReadFile("/etc/ssh/ssh_host_ed25519_key")
	if err != nil {
		return err
	}
	signer, err := gossh.ParsePrivateKey(hostKey)
	if err != nil {
		return err
	}
	srv := &ssh.Server{
		Handler:           ns.handleSSH,
		RequestHandlers:   map[string]ssh.RequestHandler{},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{},
		ChannelHandlers:   map[string]ssh.ChannelHandler{},
	}
	for k, v := range ssh.DefaultRequestHandlers {
		srv.RequestHandlers[k] = v
	}
	for k, v := range ssh.DefaultChannelHandlers {
		srv.ChannelHandlers[k] = v
	}
	for k, v := range ssh.DefaultSubsystemHandlers {
		srv.SubsystemHandlers[k] = v
	}
	srv.AddHostKey(signer)

	srv.HandleConn(c)
	return nil
}

func (ns *Impl) handleSSH(s ssh.Session) {
	lb := ns.lb
	user := s.User()
	addr := s.RemoteAddr()
	log.Printf("Handling SSH from %v for user %v", addr, user)
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		log.Printf("tsshd: rejecting non-TCP addr %T %v", addr, addr)
		s.Exit(1)
		return
	}
	tanetaddr, ok := netaddr.FromStdIP(ta.IP)
	if !ok {
		log.Printf("tsshd: rejecting unparseable addr %v", ta.IP)
		s.Exit(1)
		return
	}
	if !tsaddr.IsTailscaleIP(tanetaddr) {
		log.Printf("tsshd: rejecting non-Tailscale addr %v", ta.IP)
		s.Exit(1)
		return
	}

	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		fmt.Fprintf(s, "TODO scp etc")
		s.Exit(1)
		return
	}
	srcIPP := netaddr.IPPortFrom(tanetaddr, uint16(ta.Port))
	node, uprof, ok := lb.WhoIs(srcIPP)
	if !ok {
		fmt.Fprintf(s, "Hello, %v. I don't know who you are.\n", srcIPP)
		s.Exit(0)
		return
	}
	allow := envknob.String("TS_SSH_ALLOW_LOGIN")
	if allow == "" || uprof.LoginName != allow {
		log.Printf("ssh: access denied for %q (only allowing %q)", uprof.LoginName, allow)
		jnode, _ := json.Marshal(node)
		jprof, _ := json.Marshal(uprof)
		fmt.Fprintf(s, "Access denied.\n\nYou are node: %s\n\nYour profile: %s\n\nYou wanted %+v\n", jnode, jprof, ptyReq)
		s.Exit(1)
		return
	}

	cmd := exec.Command("/bin/bash")
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

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}
