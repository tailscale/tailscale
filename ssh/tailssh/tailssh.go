// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

// Package tailssh is an SSH server integrated into Tailscale.
package tailssh

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"inet.af/netaddr"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
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

var debugPolicyFile = envknob.String("TS_DEBUG_SSH_POLICY_FILE")

func (srv *server) sshPolicy() (_ *tailcfg.SSHPolicy, ok bool) {
	lb := srv.lb
	nm := lb.NetMap()
	if nm == nil {
		return nil, false
	}
	if pol := nm.SSHPolicy; pol != nil {
		return pol, true
	}
	if debugPolicyFile != "" {
		f, err := os.ReadFile(debugPolicyFile)
		if err != nil {
			srv.logf("error reading debug SSH policy file: %v", err)
			return nil, false
		}
		p := new(tailcfg.SSHPolicy)
		if err := json.Unmarshal(f, p); err != nil {
			srv.logf("invalid JSON in %v: %v", debugPolicyFile, err)
			return nil, false
		}
		return p, true
	}
	return nil, false
}

func (srv *server) handleSSH(s ssh.Session) {
	lb := srv.lb
	logf := srv.logf

	sshUser := s.User()
	addr := s.RemoteAddr()
	logf("Handling SSH from %v for user %v", addr, sshUser)
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

	pol, ok := srv.sshPolicy()
	if !ok {
		logf("tsshd: rejecting connection; no SSH policy")
		s.Exit(1)
		return
	}

	ptyReq, winCh, isPty := s.Pty()
	srcIPP := netaddr.IPPortFrom(tanetaddr, uint16(ta.Port))
	node, uprof, ok := lb.WhoIs(srcIPP)
	if !ok {
		fmt.Fprintf(s, "Hello, %v. I don't know who you are.\n", srcIPP)
		s.Exit(1)
		return
	}

	srcIP := srcIPP.IP()
	sctx := &sshContext{
		now:     time.Now(),
		sshUser: sshUser,
		srcIP:   srcIP,
		node:    node,
		uprof:   &uprof,
	}
	action, localUser, ok := evalSSHPolicy(pol, sctx)
	if ok && action.Message != "" {
		io.WriteString(s, action.Message)
	}
	if !ok || action.Reject {
		logf("ssh: access denied for %q from %v", uprof.LoginName, srcIP)
		s.Exit(1)
		return
	}
	if !action.Accept || action.HoldAndDelegate != "" {
		fmt.Fprintf(s, "TODO: other SSHAction outcomes")
		s.Exit(1)

	}
	if !isPty {
		fmt.Fprintf(s, "TODO scp etc\n")
		s.Exit(1)
		return
	}
	var cmd *exec.Cmd
	if os.Getuid() != 0 {
		u, err := user.Current()
		if err != nil {
			logf("failed to get current user: %v", err)
			s.Exit(1)
			return
		}
		if u.Username != localUser {
			fmt.Fprintf(s, "can't switch user\n")
			s.Exit(1)
			return
		}
		cmd = exec.Command(loginShell(u.Uid))
	} else {
		cmd = exec.Command("/usr/bin/env", "su", "-", localUser)
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	f, err := pty.Start(cmd)
	if err != nil {
		logf("running shell: %v", err)
		s.Exit(1)
		return
	}

	if action.SesssionDuration != 0 {
		t := time.AfterFunc(action.SesssionDuration, func() {
			logf("terminating SSH session from %v after max duration", srcIP)
			cmd.Process.Kill()
			f.Close()
		})
		defer t.Stop()
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

type sshContext struct {
	// now is the time to consider the present moment for the
	// purposes of rule evaluation.
	now time.Time

	// sshUser is the requested local SSH username ("root", "alice", etc).
	sshUser string

	// srcIP is the Tailscale IP that the connection came from.
	srcIP netaddr.IP

	// node is srcIP's node.
	node *tailcfg.Node

	// uprof is node's UserProfile.
	uprof *tailcfg.UserProfile
}

func evalSSHPolicy(pol *tailcfg.SSHPolicy, sctx *sshContext) (a *tailcfg.SSHAction, localUser string, ok bool) {
	for _, r := range pol.Rules {
		if a, localUser, err := matchRule(r, sctx); err == nil {
			return a, localUser, true
		}
	}
	return nil, "", false
}

// internal errors for testing; they don't escape to callers or logs.
var (
	errNilRule        = errors.New("nil rule")
	errNilAction      = errors.New("nil action")
	errRuleExpired    = errors.New("rule expired")
	errPrincipalMatch = errors.New("principal didn't match")
	errUserMatch      = errors.New("user didn't match")
)

func matchRule(r *tailcfg.SSHRule, sctx *sshContext) (a *tailcfg.SSHAction, localUser string, err error) {
	if r == nil {
		return nil, "", errNilRule
	}
	if r.Action == nil {
		return nil, "", errNilAction
	}
	if r.RuleExpires != nil && sctx.now.After(*r.RuleExpires) {
		return nil, "", errRuleExpired
	}
	if !matchesPrincipal(r.Principals, sctx) {
		return nil, "", errPrincipalMatch
	}
	if !r.Action.Reject || r.SSHUsers != nil {
		localUser = mapLocalUser(r.SSHUsers, sctx.sshUser)
		if localUser == "" {
			return nil, "", errUserMatch
		}
	}
	return r.Action, localUser, nil
}

func mapLocalUser(ruleSSHUsers map[string]string, reqSSHUser string) (localUser string) {
	if v, ok := ruleSSHUsers[reqSSHUser]; ok {
		return v
	}
	return ruleSSHUsers["*"]
}

func matchesPrincipal(ps []*tailcfg.SSHPrincipal, sctx *sshContext) bool {
	for _, p := range ps {
		if p == nil {
			continue
		}
		if p.Any {
			return true
		}
		if !p.Node.IsZero() && sctx.node != nil && p.Node == sctx.node.StableID {
			return true
		}
		if p.NodeIP != "" {
			if ip, _ := netaddr.ParseIP(p.NodeIP); ip == sctx.srcIP {
				return true
			}
		}
		if p.UserLogin != "" && sctx.uprof != nil && sctx.uprof.LoginName == p.UserLogin {
			return true
		}
	}
	return false
}

func loginShell(uid string) string {
	switch runtime.GOOS {
	case "linux":
		out, _ := exec.Command("getent", "passwd", uid).Output()
		// out is "root:x:0:0:root:/root:/bin/bash"
		f := strings.SplitN(string(out), ":", 10)
		if len(f) > 6 {
			return f[6] // shell
		}
	}
	if e := os.Getenv("SHELL"); e != "" {
		return e
	}
	return "/bin/bash"
}
