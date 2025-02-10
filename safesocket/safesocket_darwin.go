// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/version"
)

func init() {
	localTCPPortAndToken = localTCPPortAndTokenDarwin
}

const sameUserProofTokenLength = 10

type safesocketDarwin struct {
	mu              sync.Mutex
	token           string   // safesocket auth token
	port            int      // safesocket port
	sameuserproofFD *os.File // file descriptor for macos app store sameuserproof file
	sharedDir       string   // shared directory for location of sameuserproof file

	checkConn   bool        // Check macsys safesocket port before returning it
	isMacSysExt func() bool // For testing only to force macsys
}

var ssd = safesocketDarwin{
	isMacSysExt: version.IsMacSysExt,
	checkConn:   true,
	sharedDir:   "/Library/Tailscale",
}

// There are three ways a Darwin binary can be run: as the Mac App Store (macOS)
// standalone notarized (macsys), or a separate CLI (tailscale) that was
// built or downloaded.
//
// The macOS and macsys binaries can communicate directly via XPC with
// the NEPacketTunnelProvider managed tailscaled process and are responsible for
// calling SetCredentials when they need to operate as a CLI.

// A built/downloaded CLI binary will not be managing the NEPacketTunnelProvider
// hosting tailscaled directly and must source the credentials from a 'sameuserproof' file.
// This file is written to sharedDir when tailscaled/NEPacketTunnelProvider
// calls InitListenerDarwin.

// localTCPPortAndTokenDarwin returns the localhost TCP port number and auth token
// either generated, or sourced from the NEPacketTunnelProvider managed tailscaled process.
func localTCPPortAndTokenDarwin() (port int, token string, err error) {
	ssd.mu.Lock()
	defer ssd.mu.Unlock()

	if ssd.port != 0 && ssd.token != "" {
		return ssd.port, ssd.token, nil
	}

	// Credentials were not explicitly, this is likely a standalone CLI binary.
	// Fallback to reading the sameuserproof file.
	return portAndTokenFromSameUserProof()
}

// SetCredentials sets an token and port used to authenticate safesocket generated
// by the NEPacketTunnelProvider tailscaled process.  This is only used when running
// the CLI via Tailscale.app.
func SetCredentials(token string, port int) {
	ssd.mu.Lock()
	defer ssd.mu.Unlock()

	if ssd.token != "" || ssd.port != 0 {
		// Not fatal, but likely programmer error.  Credentials do not change.
		log.Printf("warning: SetCredentials credentials already set")
	}

	ssd.token = token
	ssd.port = port
}

// InitListenerDarwin initializes the listener for the CLI commands
// and localapi HTTP server and sets the port/token.  This will override
// any credentials set explicitly via SetCredentials().  Calling this mulitple times
// has no effect.  The listener and it's corresponding token/port is initialized only once.
func InitListenerDarwin(sharedDir string) (*net.Listener, error) {
	ssd.mu.Lock()
	defer ssd.mu.Unlock()

	ln := onceListener.ln
	if ln != nil {
		return ln, nil
	}

	var err error
	ln, err = localhostListener()
	if err != nil {
		log.Printf("InitListenerDarwin: listener initialization failed")
		return nil, err
	}

	port, err := localhostTCPPort()
	if err != nil {
		log.Printf("localhostTCPPort: listener initialization failed")
		return nil, err
	}

	token, err := getToken()
	if err != nil {
		log.Printf("localhostTCPPort: getToken failed")
		return nil, err
	}

	if port == 0 || token == "" {
		log.Printf("localhostTCPPort: Invalid token or port")
		return nil, fmt.Errorf("invalid localhostTCPPort: returned 0")
	}

	ssd.sharedDir = sharedDir
	ssd.token = token
	ssd.port = port

	// Write the port and token to a sameuserproof file
	err = initSameUserProofToken(sharedDir, port, token)
	if err != nil {
		// Not fatal
		log.Printf("initSameUserProofToken: failed: %v", err)
	}

	return ln, nil
}

var onceListener struct {
	once sync.Once
	ln   *net.Listener
}

func localhostTCPPort() (int, error) {
	if onceListener.ln == nil {
		return 0, fmt.Errorf("listener not initialized")
	}

	ln, err := localhostListener()
	if err != nil {
		return 0, err
	}

	return (*ln).Addr().(*net.TCPAddr).Port, nil
}

func localhostListener() (*net.Listener, error) {
	onceListener.once.Do(func() {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return
		}
		onceListener.ln = &ln
	})
	if onceListener.ln == nil {
		return nil, fmt.Errorf("failed to get TCP listener")
	}
	return onceListener.ln, nil
}

var onceToken struct {
	once  sync.Once
	token string
}

func getToken() (string, error) {
	onceToken.once.Do(func() {
		buf := make([]byte, sameUserProofTokenLength)
		if _, err := crand.Read(buf); err != nil {
			return
		}
		t := fmt.Sprintf("%x", buf)
		onceToken.token = t
	})
	if onceToken.token == "" {
		return "", fmt.Errorf("failed to generate token")
	}

	return onceToken.token, nil
}

// initSameUserProofToken writes the port and token to a sameuserproof
// file owned by the current user.  We leave the file open to allow us
// to discover it via lsof.
//
// "sameuserproof" is intended to convey that the user attempting to read
// the credentials from the file is the same user that wrote them.  For
// standalone macsys where tailscaled is running as root, we set group
// permissions to allow users in the admin group to read the file.
func initSameUserProofToken(sharedDir string, port int, token string) error {
	var err error

	// Guard against bad sharedDir
	old, err := os.ReadDir(sharedDir)
	if err == os.ErrNotExist {
		log.Printf("failed to read shared dir %s: %v", sharedDir, err)
		return err
	}

	// Remove all old sameuserproof files
	for _, fi := range old {
		if name := fi.Name(); strings.HasPrefix(name, "sameuserproof-") {
			err := os.Remove(filepath.Join(sharedDir, name))
			if err != nil {
				log.Printf("failed to remove %s: %v", name, err)
			}
		}
	}

	var baseFile string
	var perm fs.FileMode
	if ssd.isMacSysExt() {
		perm = 0640 // allow wheel to read
		baseFile = fmt.Sprintf("sameuserproof-%d", port)
		portFile := filepath.Join(sharedDir, "ipnport")
		err := os.Remove(portFile)
		if err != nil {
			log.Printf("failed to remove portfile %s: %v", portFile, err)
		}
		symlinkErr := os.Symlink(fmt.Sprint(port), portFile)
		if symlinkErr != nil {
			log.Printf("failed to symlink portfile: %v", symlinkErr)
		}
	} else {
		perm = 0666
		baseFile = fmt.Sprintf("sameuserproof-%d-%s", port, token)
	}

	path := filepath.Join(sharedDir, baseFile)
	ssd.sameuserproofFD, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	log.Printf("initSameUserProofToken : done=%v", err == nil)

	if ssd.isMacSysExt() && err == nil {
		fmt.Fprintf(ssd.sameuserproofFD, "%s\n", token)

		// Macsys runs as root so ownership of this file will be
		// root/wheel.  Change ownership to root/admin which will let all members
		// of the admin group to read it.
		unix.Fchown(int(ssd.sameuserproofFD.Fd()), 0, 80 /* admin */)
	}

	return err
}

// readMacsysSameuserproof returns the localhost TCP port number and auth token
// from a sameuserproof file written to /Library/Tailscale.
//
// In that case the files are:
//
//	/Library/Tailscale/ipnport => $port (symlink with localhost port number target)
//	/Library/Tailscale/sameuserproof-$port is a file containing only the auth token as a hex string.
func readMacsysSameUserProof() (port int, token string, err error) {
	portStr, err := os.Readlink(filepath.Join(ssd.sharedDir, "ipnport"))
	if err != nil {
		return 0, "", err
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return 0, "", err
	}
	authb, err := os.ReadFile(filepath.Join(ssd.sharedDir, "sameuserproof-"+portStr))
	if err != nil {
		return 0, "", err
	}
	auth := strings.TrimSpace(string(authb))
	if auth == "" {
		return 0, "", errors.New("empty auth token in sameuserproof file")
	}

	if ssd.checkConn {
		// Files may be stale and there is no guarantee that the  sameuserproof
		// derived port is open and valid. Check it before returning it.
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+portStr, time.Second)
		if err != nil {
			return 0, "", err
		}
		conn.Close()
	}

	return port, auth, nil
}

// readMacosSameUserProof searches for open sameuserproof files belonging
// to the current user and the IPNExtension (macOS App Store) process and returns a
// port and token.
func readMacosSameUserProof() (port int, token string, err error) {
	cmd := exec.Command("lsof",
		"-n",                             // numeric sockets; don't do DNS lookups, etc
		"-a",                             // logical AND remaining options
		fmt.Sprintf("-u%d", os.Getuid()), // process of same user only
		"-c", "IPNExtension",             // starting with IPNExtension
		"-F", // machine-readable output
	)
	out, err := cmd.Output()

	if err == nil {
		bs := bufio.NewScanner(bytes.NewReader(out))
		subStr := []byte(".tailscale.ipn.macos/sameuserproof-")
		for bs.Scan() {
			line := bs.Bytes()
			i := bytes.Index(line, subStr)
			if i == -1 {
				continue
			}
			f := strings.SplitN(string(line[i+len(subStr):]), "-", 2)
			if len(f) != 2 {
				continue
			}
			portStr, token := f[0], f[1]
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return 0, "", fmt.Errorf("invalid port %q found in lsof", portStr)
			}

			return port, token, nil
		}
	}
	return 0, "", ErrTokenNotFound
}

func portAndTokenFromSameUserProof() (port int, token string, err error) {
	if port, token, err := readMacosSameUserProof(); err == nil {
		return port, token, nil
	}

	if port, token, err := readMacsysSameUserProof(); err == nil {
		return port, token, nil
	}

	return 0, "", err
}
