// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package driveimpl

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/drive"
	"tailscale.com/drive/driveimpl/compositedav"
	"tailscale.com/drive/driveimpl/dirfs"
	"tailscale.com/drive/driveimpl/shared"
	"tailscale.com/safesocket"
	"tailscale.com/types/logger"
)

func NewFileSystemForRemote(logf logger.Logf) *FileSystemForRemote {
	if logf == nil {
		logf = log.Printf
	}
	fs := &FileSystemForRemote{
		logf:        logf,
		lockSystem:  webdav.NewMemLS(),
		children:    make(map[string]*compositedav.Child),
		userServers: make(map[string]*userServer),
	}
	return fs
}

// FileSystemForRemote implements drive.FileSystemForRemote.
type FileSystemForRemote struct {
	logf       logger.Logf
	lockSystem webdav.LockSystem

	// mu guards the below values. Acquire a write lock before updating any of
	// them, acquire a read lock before reading any of them.
	mu sync.RWMutex
	// fileServerTokenAndAddr is the secretToken|fileserverAddress
	fileServerTokenAndAddr string
	shares                 []*drive.Share
	children               map[string]*compositedav.Child
	userServers            map[string]*userServer
}

// SetFileServerAddr implements drive.FileSystemForRemote.
func (s *FileSystemForRemote) SetFileServerAddr(addr string) {
	s.mu.Lock()
	s.fileServerTokenAndAddr = addr
	s.mu.Unlock()
}

// SetShares implements drive.FileSystemForRemote. Shares must be sorted
// according to drive.CompareShares.
func (s *FileSystemForRemote) SetShares(shares []*drive.Share) {
	userServers := make(map[string]*userServer)
	if drive.AllowShareAs() {
		// Set up per-user server by running the current executable as an
		// unprivileged user in order to avoid privilege escalation.
		executable, err := os.Executable()
		if err != nil {
			s.logf("can't find executable: %v", err)
			return
		}

		for _, share := range shares {
			p, found := userServers[share.As]
			if !found {
				p = &userServer{
					logf:       s.logf,
					username:   share.As,
					executable: executable,
				}
				userServers[share.As] = p
			}
			p.shares = append(p.shares, share)
		}
		for _, p := range userServers {
			go p.runLoop()
		}
	}

	children := make(map[string]*compositedav.Child, len(shares))
	for _, share := range shares {
		children[share.Name] = s.buildChild(share)
	}

	s.mu.Lock()
	s.shares = shares
	oldUserServers := s.userServers
	oldChildren := s.children
	s.children = children
	s.userServers = userServers
	s.mu.Unlock()

	s.stopUserServers(oldUserServers)
	s.closeChildren(oldChildren)
}

func (s *FileSystemForRemote) buildChild(share *drive.Share) *compositedav.Child {
	getTokenAndAddr := func(shareName string) (string, string, error) {
		s.mu.RLock()
		var share *drive.Share
		i, shareFound := slices.BinarySearchFunc(s.shares, shareName, func(s *drive.Share, name string) int {
			return strings.Compare(s.Name, name)
		})
		if shareFound {
			share = s.shares[i]
		}
		userServers := s.userServers
		fileServerTokenAndAddr := s.fileServerTokenAndAddr
		s.mu.RUnlock()

		if !shareFound {
			return "", "", fmt.Errorf("unknown share %v", shareName)
		}

		var tokenAndAddr string
		if !drive.AllowShareAs() {
			tokenAndAddr = fileServerTokenAndAddr
		} else {
			userServer, found := userServers[share.As]
			if found {
				userServer.mu.RLock()
				tokenAndAddr = userServer.tokenAndAddr
				userServer.mu.RUnlock()
			}
		}

		if tokenAndAddr == "" {
			return "", "", fmt.Errorf("unable to determine address for share %v", shareName)
		}

		parts := strings.Split(tokenAndAddr, "|")
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid address for share %v", shareName)
		}

		return parts[0], parts[1], nil
	}

	return &compositedav.Child{
		Child: &dirfs.Child{
			Name: share.Name,
		},
		BaseURL: func() (string, error) {
			secretToken, _, err := getTokenAndAddr(share.Name)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("http://%s/%s/%s", hex.EncodeToString([]byte(share.Name)), secretToken, url.PathEscape(share.Name)), nil
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, shareAddr string) (net.Conn, error) {
				shareNameHex, _, err := net.SplitHostPort(shareAddr)
				if err != nil {
					return nil, fmt.Errorf("unable to parse share address %v: %w", shareAddr, err)
				}

				// We had to encode the share name in hex to make sure it's a valid hostname
				shareNameBytes, err := hex.DecodeString(shareNameHex)
				if err != nil {
					return nil, fmt.Errorf("unable to decode share name from host %v: %v", shareNameHex, err)
				}
				shareName := string(shareNameBytes)

				_, addr, err := getTokenAndAddr(shareName)
				if err != nil {
					return nil, err
				}

				_, err = netip.ParseAddrPort(addr)
				if err == nil {
					// this is a regular network address, dial normally
					var std net.Dialer
					return std.DialContext(ctx, "tcp", addr)
				}
				// assume this is a safesocket address
				return safesocket.ConnectContext(ctx, addr)
			},
		},
	}
}

// ServeHTTPWithPerms implements drive.FileSystemForRemote.
func (s *FileSystemForRemote) ServeHTTPWithPerms(permissions drive.Permissions, w http.ResponseWriter, r *http.Request) {
	isWrite := writeMethods[r.Method]
	if isWrite {
		share := shared.CleanAndSplit(r.URL.Path)[0]
		switch permissions.For(share) {
		case drive.PermissionNone:
			// If we have no permissions to this share, treat it as not found
			// to avoid leaking any information about the share's existence.
			http.Error(w, "not found", http.StatusNotFound)
			return
		case drive.PermissionReadOnly:
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
	}

	s.mu.RLock()
	childrenMap := s.children
	s.mu.RUnlock()

	children := make([]*compositedav.Child, 0, len(childrenMap))
	// filter out shares to which the connecting principal has no access
	for name, child := range childrenMap {
		if permissions.For(name) == drive.PermissionNone {
			continue
		}

		children = append(children, child)
	}

	h := compositedav.Handler{
		Logf: s.logf,
	}
	h.SetChildren("", children...)
	h.ServeHTTP(w, r)
}

func (s *FileSystemForRemote) stopUserServers(userServers map[string]*userServer) {
	for _, server := range userServers {
		if err := server.Close(); err != nil {
			s.logf("error closing taildrive user server: %v", err)
		}
	}
}

func (s *FileSystemForRemote) closeChildren(children map[string]*compositedav.Child) {
	for _, child := range children {
		child.CloseIdleConnections()
	}
}

// Close() implements drive.FileSystemForRemote.
func (s *FileSystemForRemote) Close() error {
	s.mu.Lock()
	userServers := s.userServers
	children := s.children
	s.userServers = make(map[string]*userServer)
	s.children = make(map[string]*compositedav.Child)
	s.mu.Unlock()

	s.stopUserServers(userServers)
	s.closeChildren(children)
	return nil
}

// userServer runs tailscaled serve-taildrive to serve webdav content for the
// given Shares. All Shares are assumed to have the same Share.As, and the
// content is served as that Share.As user.
type userServer struct {
	logf       logger.Logf
	shares     []*drive.Share
	username   string
	executable string

	// mu guards the below values. Acquire a write lock before updating any of
	// them, acquire a read lock before reading any of them.
	mu           sync.RWMutex
	cmd          *exec.Cmd
	tokenAndAddr string
	closed       bool
}

func (s *userServer) Close() error {
	s.mu.Lock()
	cmd := s.cmd
	s.closed = true
	s.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		return cmd.Process.Kill()
	}
	// not running, that's okay
	return nil
}

func (s *userServer) runLoop() {
	maxSleepTime := 30 * time.Second
	consecutiveFailures := float64(0)
	var timeOfLastFailure time.Time
	for {
		s.mu.RLock()
		closed := s.closed
		s.mu.RUnlock()
		if closed {
			return
		}

		err := s.run()
		now := time.Now()
		timeSinceLastFailure := now.Sub(timeOfLastFailure)
		timeOfLastFailure = now
		if timeSinceLastFailure < maxSleepTime {
			consecutiveFailures++
		} else {
			consecutiveFailures = 1
		}
		sleepTime := time.Duration(math.Pow(2, consecutiveFailures)) * time.Millisecond
		if sleepTime > maxSleepTime {
			sleepTime = maxSleepTime
		}
		s.logf("user server % v stopped with error %v, will try again in %v", s.executable, err, sleepTime)
		time.Sleep(sleepTime)
	}
}

// Run runs the user server using the configured executable. This function only
// works on UNIX systems, but those are the only ones on which we use
// userServers anyway.
func (s *userServer) run() error {
	// set up the command
	args := []string{"serve-taildrive"}
	for _, s := range s.shares {
		args = append(args, s.Name, s.Path)
	}
	var cmd *exec.Cmd
	if su := s.canSU(); su != "" {
		s.logf("starting taildrive file server as user %q", s.username)
		// Quote and escape arguments. Use single quotes to prevent shell substitutions.
		for i, arg := range args {
			args[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
		}
		cmdString := fmt.Sprintf("%s %s", s.executable, strings.Join(args, " "))
		allArgs := []string{s.username, "-c", cmdString}
		cmd = exec.Command(su, allArgs...)
	} else {
		// If we were root, we should have been able to sudo as a specific
		// user, but let's check just to make sure, since we never want to
		// access shared folders as root.
		err := s.assertNotRoot()
		if err != nil {
			return err
		}
		s.logf("starting taildrive file server as ourselves")
		cmd = exec.Command(s.executable, args...)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	defer stdout.Close()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	defer stderr.Close()

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	s.mu.Lock()
	s.cmd = cmd
	s.mu.Unlock()

	// read address
	stdoutScanner := bufio.NewScanner(stdout)
	stdoutScanner.Scan()
	if stdoutScanner.Err() != nil {
		return fmt.Errorf("read addr: %w", stdoutScanner.Err())
	}
	addr := stdoutScanner.Text()
	// send the rest of stdout and stderr to logger to avoid blocking
	go func() {
		for stdoutScanner.Scan() {
			s.logf("tailscaled serve-taildrive stdout: %v", stdoutScanner.Text())
		}
	}()
	stderrScanner := bufio.NewScanner(stderr)
	go func() {
		for stderrScanner.Scan() {
			s.logf("tailscaled serve-taildrive stderr: %v", stderrScanner.Text())
		}
	}()
	s.mu.Lock()
	s.tokenAndAddr = strings.TrimSpace(addr)
	s.mu.Unlock()
	return cmd.Wait()
}

var writeMethods = map[string]bool{
	"PUT":       true,
	"POST":      true,
	"COPY":      true,
	"LOCK":      true,
	"UNLOCK":    true,
	"MKCOL":     true,
	"MOVE":      true,
	"PROPPATCH": true,
	"DELETE":    true,
}

// canSU checks whether the current process can run su with the right username.
// If su can be run, this returns the path to the su command.
// If not, this returns the empty string "".
func (s *userServer) canSU() string {
	su, err := exec.LookPath("su")
	if err != nil {
		s.logf("can't find su command: %v", err)
		return ""
	}

	// First try to execute su <user> -c true to make sure we can su.
	err = exec.Command(
		su,
		s.username,
		"-c", "true",
	).Run()
	if err != nil {
		s.logf("su check failed: %s", err)
		return ""
	}

	return su
}

// assertNotRoot returns an error if the current user has UID 0 or if we cannot
// determine the current user.
//
// On Linux, root users will always have UID 0.
//
// On BSD, root users should always have UID 0.
func (s *userServer) assertNotRoot() error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("assertNotRoot failed to find current user: %s", err)
	}
	if u.Uid == "0" {
		return fmt.Errorf("%q is root", u.Name)
	}
	return nil
}
