// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailfsimpl

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/safesocket"
	"tailscale.com/tailfs"
	"tailscale.com/tailfs/tailfsimpl/compositefs"
	"tailscale.com/tailfs/tailfsimpl/shared"
	"tailscale.com/tailfs/tailfsimpl/webdavfs"
	"tailscale.com/types/logger"
)

func NewFileSystemForRemote(logf logger.Logf) *FileSystemForRemote {
	if logf == nil {
		logf = log.Printf
	}
	fs := &FileSystemForRemote{
		logf:        logf,
		lockSystem:  webdav.NewMemLS(),
		fileSystems: make(map[string]webdav.FileSystem),
		userServers: make(map[string]*userServer),
	}
	return fs
}

// FileSystemForRemote implements tailfs.FileSystemForRemote.
type FileSystemForRemote struct {
	logf       logger.Logf
	lockSystem webdav.LockSystem

	// mu guards the below values. Acquire a write lock before updating any of
	// them, acquire a read lock before reading any of them.
	mu             sync.RWMutex
	fileServerAddr string
	shares         map[string]*tailfs.Share
	fileSystems    map[string]webdav.FileSystem
	userServers    map[string]*userServer
}

// SetFileServerAddr implements tailfs.FileSystemForRemote.
func (s *FileSystemForRemote) SetFileServerAddr(addr string) {
	s.mu.Lock()
	s.fileServerAddr = addr
	s.mu.Unlock()
}

// SetShares implements tailfs.FileSystemForRemote.
func (s *FileSystemForRemote) SetShares(shares map[string]*tailfs.Share) {
	userServers := make(map[string]*userServer)
	if tailfs.AllowShareAs() {
		// set up per-user server
		for _, share := range shares {
			p, found := userServers[share.As]
			if !found {
				p = &userServer{
					logf: s.logf,
				}
				userServers[share.As] = p
			}
			p.shares = append(p.shares, share)
		}
		for _, p := range userServers {
			go p.runLoop()
		}
	}

	fileSystems := make(map[string]webdav.FileSystem, len(shares))
	for _, share := range shares {
		fileSystems[share.Name] = s.buildWebDAVFS(share)
	}

	s.mu.Lock()
	s.shares = shares
	oldFileSystems := s.fileSystems
	oldUserServers := s.userServers
	s.fileSystems = fileSystems
	s.userServers = userServers
	s.mu.Unlock()

	s.stopUserServers(oldUserServers)
	s.closeFileSystems(oldFileSystems)
}

func (s *FileSystemForRemote) buildWebDAVFS(share *tailfs.Share) webdav.FileSystem {
	return webdavfs.New(webdavfs.Options{
		Logf: s.logf,
		URL:  fmt.Sprintf("http://%v/%v", hex.EncodeToString([]byte(share.Name)), share.Name),
		Transport: &http.Transport{
			Dial: func(_, shareAddr string) (net.Conn, error) {
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

				s.mu.RLock()
				share, shareFound := s.shares[shareName]
				userServers := s.userServers
				fileServerAddr := s.fileServerAddr
				s.mu.RUnlock()

				if !shareFound {
					return nil, fmt.Errorf("unknown share %v", shareName)
				}

				var addr string
				if !tailfs.AllowShareAs() {
					addr = fileServerAddr
				} else {
					userServer, found := userServers[share.As]
					if found {
						userServer.mu.RLock()
						addr = userServer.addr
						userServer.mu.RUnlock()
					}
				}

				if addr == "" {
					return nil, fmt.Errorf("unable to determine address for share %v", shareName)
				}

				_, err = netip.ParseAddrPort(addr)
				if err == nil {
					// this is a regular network address, dial normally
					return net.Dial("tcp", addr)
				}
				// assume this is a safesocket address
				return safesocket.Connect(addr)
			},
		},
		StatRoot: true,
	})
}

// ServeHTTPWithPerms implements tailfs.FileSystemForRemote.
func (s *FileSystemForRemote) ServeHTTPWithPerms(permissions tailfs.Permissions, w http.ResponseWriter, r *http.Request) {
	isWrite := writeMethods[r.Method]
	if isWrite {
		share := shared.CleanAndSplit(r.URL.Path)[0]
		switch permissions.For(share) {
		case tailfs.PermissionNone:
			// If we have no permissions to this share, treat it as not found
			// to avoid leaking any information about the share's existence.
			http.Error(w, "not found", http.StatusNotFound)
			return
		case tailfs.PermissionReadOnly:
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
	}

	s.mu.RLock()
	fileSystems := s.fileSystems
	s.mu.RUnlock()

	children := make([]*compositefs.Child, 0, len(fileSystems))
	// filter out shares to which the connecting principal has no access
	for name, fs := range fileSystems {
		if permissions.For(name) == tailfs.PermissionNone {
			continue
		}

		children = append(children, &compositefs.Child{Name: name, FS: fs})
	}

	cfs := compositefs.New(
		compositefs.Options{
			Logf:         s.logf,
			StatChildren: true,
		})
	cfs.SetChildren(children...)
	h := webdav.Handler{
		FileSystem: cfs,
		LockSystem: s.lockSystem,
	}
	h.ServeHTTP(w, r)
}

func (s *FileSystemForRemote) stopUserServers(userServers map[string]*userServer) {
	for _, server := range userServers {
		if err := server.Close(); err != nil {
			s.logf("error closing tailfs user server: %v", err)
		}
	}
}

func (s *FileSystemForRemote) closeFileSystems(fileSystems map[string]webdav.FileSystem) {
	for _, fs := range fileSystems {
		closer, ok := fs.(interface{ Close() error })
		if ok {
			if err := closer.Close(); err != nil {
				s.logf("error closing tailfs filesystem: %v", err)
			}
		}
	}
}

// Close() implements tailfs.FileSystemForRemote.
func (s *FileSystemForRemote) Close() error {
	s.mu.Lock()
	userServers := s.userServers
	fileSystems := s.fileSystems
	s.mu.Unlock()

	s.stopUserServers(userServers)
	s.closeFileSystems(fileSystems)
	return nil
}

// userServer runs tailscaled serve-tailfs to serve webdav content for the
// given Shares. All Shares are assumed to have the same Share.As, and the
// content is served as that Share.As user.
type userServer struct {
	logf   logger.Logf
	shares []*tailfs.Share

	// mu guards the below values. Acquire a write lock before updating any of
	// them, acquire a read lock before reading any of them.
	mu     sync.RWMutex
	cmd    *exec.Cmd
	addr   string
	closed bool
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
	executable, err := os.Executable()
	if err != nil {
		s.logf("can't find executable: %v", err)
		return
	}
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

		err := s.run(executable)
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
		s.logf("user server % v stopped with error %v, will try again in %v", executable, err, sleepTime)
		time.Sleep(sleepTime)
	}
}

// Run runs the executable (tailscaled). This function only works on UNIX systems,
// but those are the only ones on which we use userServers anyway.
func (s *userServer) run(executable string) error {
	// set up the command
	args := []string{"serve-tailfs"}
	for _, s := range s.shares {
		args = append(args, s.Name, s.Path)
	}
	allArgs := []string{"-u", s.shares[0].As, executable}
	allArgs = append(allArgs, args...)
	cmd := exec.Command("sudo", allArgs...)
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
			s.logf("tailscaled serve-tailfs stdout: %v", stdoutScanner.Text())
		}
	}()
	stderrScanner := bufio.NewScanner(stderr)
	go func() {
		for stderrScanner.Scan() {
			s.logf("tailscaled serve-tailfs stderr: %v", stderrScanner.Text())
		}
	}()
	s.mu.Lock()
	s.addr = strings.TrimSpace(addr)
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
}
