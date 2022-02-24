// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (darwin && !ios)
// +build linux darwin,!ios

// Package tailssh is an SSH server integrated into Tailscale.
package tailssh

import (
	"context"
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
	srv := &server{lb, logf}
	ss, err := srv.newSSHServer()
	if err != nil {
		return err
	}
	ss.HandleConn(c)
	return nil
}

func (srv *server) newSSHServer() (*ssh.Server, error) {
	ss := &ssh.Server{
		Handler:           srv.handleSSH,
		RequestHandlers:   map[string]ssh.RequestHandler{},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{},
		ChannelHandlers:   map[string]ssh.ChannelHandler{},
	}
	for k, v := range ssh.DefaultRequestHandlers {
		ss.RequestHandlers[k] = v
	}
	for k, v := range ssh.DefaultChannelHandlers {
		ss.ChannelHandlers[k] = v
	}
	for k, v := range ssh.DefaultSubsystemHandlers {
		ss.SubsystemHandlers[k] = v
	}
	keys, err := srv.lb.GetSSH_HostKeys()
	if err != nil {
		return nil, err
	}
	for _, signer := range keys {
		ss.AddHostKey(signer)
	}
	return ss, nil
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

	srcIPP := netaddr.IPPortFrom(tanetaddr, uint16(ta.Port))
	node, uprof, ok := lb.WhoIs(srcIPP)
	if !ok {
		fmt.Fprintf(s, "Hello, %v. I don't know who you are.\n", srcIPP)
		s.Exit(1)
		return
	}

	srcIP := srcIPP.IP()
	ci := &sshConnInfo{
		now:     time.Now(),
		sshUser: sshUser,
		srcIP:   srcIP,
		node:    node,
		uprof:   &uprof,
	}
	action, localUser, ok := evalSSHPolicy(pol, ci)
	if ok && action.Message != "" {
		io.WriteString(s.Stderr(), strings.Replace(action.Message, "\n", "\r\n", -1))
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
	lu, err := user.Lookup(localUser)
	if err != nil {
		logf("ssh: user Lookup %q: %v", localUser, err)
		s.Exit(1)
	}

	var ctx context.Context = context.Background()
	if action.SesssionDuration != 0 {
		sctx := newSSHContext()
		ctx = sctx
		t := time.AfterFunc(action.SesssionDuration, func() {
			sctx.CloseWithError(userVisibleError{
				fmt.Sprintf("Session timeout of %v elapsed.", action.SesssionDuration),
				context.DeadlineExceeded,
			})
		})
		defer t.Stop()
	}
	srv.handleAcceptedSSH(ctx, s, ci, lu)
}

// handleAcceptedSSH handles s once it's been accepted and determined
// that it should run as local system user lu.
//
// When ctx is done, the session is forcefully terminated. If its Err
// is an SSHTerminationError, its SSHTerminationMessage is sent to the
// user.
func (srv *server) handleAcceptedSSH(ctx context.Context, s ssh.Session, ci *sshConnInfo, lu *user.User) {
	logf := srv.logf
	localUser := lu.Username

	var err error
	ptyReq, winCh, isPty := s.Pty()
	logf("ssh: connection from %v %v to %v@ => %q. command = %q, env = %q", ci.srcIP, ci.uprof.LoginName, ci.sshUser, localUser, s.Command(), s.Environ())
	var cmd *exec.Cmd
	if euid := os.Geteuid(); euid != 0 {
		if lu.Uid != fmt.Sprint(euid) {
			logf("ssh: can't switch to user %q from process euid %v", localUser, euid)
			fmt.Fprintf(s, "can't switch user\n")
			s.Exit(1)
			return
		}
		cmd = exec.Command(loginShell(lu.Uid))
		if rawCmd := s.RawCommand(); rawCmd != "" {
			cmd.Args = append(cmd.Args, "-c", rawCmd)
		}
	} else {
		if rawCmd := s.RawCommand(); rawCmd != "" {
			cmd = exec.Command("/usr/bin/env", "su", "-c", rawCmd, localUser)
			// TODO: and Env for PATH, SSH_CONNECTION, SSH_CLIENT, XDG_SESSION_TYPE, XDG_*, etc
		} else {
			cmd = exec.Command("/usr/bin/env", "su", "-", localUser)
		}
	}
	cmd.Dir = lu.HomeDir
	cmd.Env = append(cmd.Env, envForUser(lu)...)
	if ptyReq.Term != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}
	// TODO(bradfitz,maisem): also blend in user's s.Environ()
	logf("Running: %q", cmd.Args)
	var toCmd io.WriteCloser
	var fromCmd io.ReadCloser
	if isPty {
		f, err := pty.StartWithSize(cmd, &pty.Winsize{
			Rows: uint16(ptyReq.Window.Width),
			Cols: uint16(ptyReq.Window.Height),
		})
		if err != nil {
			logf("running shell: %v", err)
			s.Exit(1)
			return
		}
		defer f.Close()
		toCmd = f
		fromCmd = f
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
	} else {
		stdin, stdout, stderr, err := startWithStdPipes(cmd)
		if err != nil {
			logf("ssh: start error: %f", err)
			s.Exit(1)
			return
		}
		fromCmd, toCmd = stdout, stdin
		go func() { io.Copy(s.Stderr(), stderr) }()
	}

	if ctx.Done() != nil {
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-done:
			case <-ctx.Done():
				err := ctx.Err()
				if serr, ok := err.(SSHTerminationError); ok {
					msg := serr.SSHTerminationMessage()
					if msg != "" {
						io.WriteString(s.Stderr(), "\r\n\r\n"+msg+"\r\n\r\n")
					}
				}
				logf("terminating SSH session from %v: %v", ci.srcIP, err)
				cmd.Process.Kill()
			}
		}()
	}

	go func() {
		_, err := io.Copy(toCmd, s) // stdin
		logf("ssh: stdin copy: %v", err)
		toCmd.Close()
	}()
	go func() {
		_, err := io.Copy(s, fromCmd) // stdout
		logf("ssh: stdout copy: %v", err)
	}()

	err = cmd.Wait()
	if err == nil {
		logf("ssh: Wait: ok")
		s.Exit(0)
		return
	}
	if ee, ok := err.(*exec.ExitError); ok {
		code := ee.ProcessState.ExitCode()
		logf("ssh: Wait: code=%v", code)
		s.Exit(code)
		return
	}

	logf("ssh: Wait: %v", err)
	s.Exit(1)
	return
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

type sshConnInfo struct {
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

func evalSSHPolicy(pol *tailcfg.SSHPolicy, ci *sshConnInfo) (a *tailcfg.SSHAction, localUser string, ok bool) {
	for _, r := range pol.Rules {
		if a, localUser, err := matchRule(r, ci); err == nil {
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

func matchRule(r *tailcfg.SSHRule, ci *sshConnInfo) (a *tailcfg.SSHAction, localUser string, err error) {
	if r == nil {
		return nil, "", errNilRule
	}
	if r.Action == nil {
		return nil, "", errNilAction
	}
	if r.RuleExpires != nil && ci.now.After(*r.RuleExpires) {
		return nil, "", errRuleExpired
	}
	if !matchesPrincipal(r.Principals, ci) {
		return nil, "", errPrincipalMatch
	}
	if !r.Action.Reject || r.SSHUsers != nil {
		localUser = mapLocalUser(r.SSHUsers, ci.sshUser)
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

func matchesPrincipal(ps []*tailcfg.SSHPrincipal, ci *sshConnInfo) bool {
	for _, p := range ps {
		if p == nil {
			continue
		}
		if p.Any {
			return true
		}
		if !p.Node.IsZero() && ci.node != nil && p.Node == ci.node.StableID {
			return true
		}
		if p.NodeIP != "" {
			if ip, _ := netaddr.ParseIP(p.NodeIP); ip == ci.srcIP {
				return true
			}
		}
		if p.UserLogin != "" && ci.uprof != nil && ci.uprof.LoginName == p.UserLogin {
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
			return strings.TrimSpace(f[6]) // shell
		}
	}
	if e := os.Getenv("SHELL"); e != "" {
		return e
	}
	return "/bin/bash"
}

func startWithStdPipes(cmd *exec.Cmd) (stdin io.WriteCloser, stdout, stderr io.ReadCloser, err error) {
	defer func() {
		if err != nil {
			for _, c := range []io.Closer{stdin, stdout, stderr} {
				if c != nil {
					c.Close()
				}
			}
		}
	}()
	stdin, err = cmd.StdinPipe()
	if err != nil {
		return
	}
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err = cmd.StderrPipe()
	if err != nil {
		return
	}
	err = cmd.Start()
	return
}

func envForUser(u *user.User) []string {
	return []string{
		fmt.Sprintf("SHELL=" + loginShell(u.Uid)),
		fmt.Sprintf("USER=" + u.Username),
		fmt.Sprintf("HOME=" + u.HomeDir),
	}
}
