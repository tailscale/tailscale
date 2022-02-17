// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

// Package tailssh is an SSH server integrated into Tailscale.
package tailssh

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"inet.af/netaddr"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
)

// TODO(bradfitz): this is all very temporary as code is temporarily
// being moved around; it will be restructured and documented in
// following commits.

// Handle handles an SSH connection from c.
func Handle(logf logger.Logf, lb *ipnlocal.LocalBackend, c net.Conn) error {
	sshd := &server{lb, logf}
	srv := &ssh.Server{
		Handler:           sshd.handleSSH,
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
	keys, err := lb.GetSSH_HostKeys()
	if err != nil {
		return err
	}
	for _, signer := range keys {
		srv.AddHostKey(signer)
	}

	srv.HandleConn(c)
	return nil
}

type server struct {
	lb   *ipnlocal.LocalBackend
	logf logger.Logf
}

func (srv *server) handleSSH(s ssh.Session) {
	lb := srv.lb
	logf := srv.logf

	user := s.User()
	addr := s.RemoteAddr()
	logf("Handling SSH from %v for user %v", addr, user)
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		logf("tsshd: rejecting non-TCP addr %T %v", addr, addr)
		s.Exit(1)
		return
	}
	tanetaddr, ok := netaddr.FromStdIP(ta.IP)
	if !ok {
		logf("tsshd: rejecting unparseable addr %v", ta.IP)
		s.Exit(1)
		return
	}
	if !tsaddr.IsTailscaleIP(tanetaddr) {
		logf("tsshd: rejecting non-Tailscale addr %v", ta.IP)
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
		logf("ssh: access denied for %q (only allowing %q)", uprof.LoginName, allow)
		jnode, _ := json.Marshal(node)
		jprof, _ := json.Marshal(uprof)
		fmt.Fprintf(s, "Access denied.\n\nYou are node: %s\n\nYour profile: %s\n\nYou wanted %+v\n", jnode, jprof, ptyReq)
		s.Exit(1)
		return
	}

	var cmd *exec.Cmd
	sshUser := s.User()
	if os.Getuid() != 0 || sshUser == "root" {
		cmd = exec.Command("/bin/bash")
	} else {
		cmd = exec.Command("/usr/bin/env", "su", "-", sshUser)
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	f, err := pty.Start(cmd)
	if err != nil {
		logf("running shell: %v", err)
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
