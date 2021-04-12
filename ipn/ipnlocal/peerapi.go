// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"inet.af/netaddr"
	"tailscale.com/ipn"
	"tailscale.com/net/interfaces"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine"
)

var initListenConfig func(*net.ListenConfig, netaddr.IP, *interfaces.State, string) error

type peerAPIServer struct {
	b          *LocalBackend
	rootDir    string
	tunName    string
	selfNode   *tailcfg.Node
	knownEmpty syncs.AtomicBool

	// directFileMode is whether we're writing files directly to a
	// download directory (as *.partial files), rather than making
	// the frontend retrieve it over localapi HTTP and write it
	// somewhere itself. This is used on GUI macOS version.
	directFileMode bool
}

const partialSuffix = ".partial"

func (s *peerAPIServer) diskPath(baseName string) (fullPath string, ok bool) {
	clean := path.Clean(baseName)
	if clean != baseName ||
		clean == "." ||
		strings.ContainsAny(clean, `/\`) ||
		strings.HasSuffix(clean, partialSuffix) {
		return "", false
	}
	return filepath.Join(s.rootDir, strings.ReplaceAll(url.PathEscape(baseName), ":", "%3a")), true
}

// hasFilesWaiting reports whether any files are buffered in the
// tailscaled daemon storage.
func (s *peerAPIServer) hasFilesWaiting() bool {
	if s.rootDir == "" || s.directFileMode {
		return false
	}
	if s.knownEmpty.Get() {
		// Optimization: this is usually empty, so avoid opening
		// the directory and checking. We can't cache the actual
		// has-files-or-not values as the macOS/iOS client might
		// in the future use+delete the files directly. So only
		// keep this negative cache.
		return false
	}
	f, err := os.Open(s.rootDir)
	if err != nil {
		return false
	}
	defer f.Close()
	for {
		des, err := f.ReadDir(10)
		for _, de := range des {
			if strings.HasSuffix(de.Name(), partialSuffix) {
				continue
			}
			if de.Type().IsRegular() {
				return true
			}
		}
		if err == io.EOF {
			s.knownEmpty.Set(true)
		}
		if err != nil {
			break
		}
	}
	return false
}

// WaitingFile is a JSON-marshaled struct sent by the localapi to pick
// up queued files.
type WaitingFile struct {
	Name string
	Size int64
}

func (s *peerAPIServer) WaitingFiles() (ret []WaitingFile, err error) {
	if s.rootDir == "" {
		return nil, errors.New("peerapi disabled; no storage configured")
	}
	if s.directFileMode {
		return nil, nil
	}
	f, err := os.Open(s.rootDir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	for {
		des, err := f.ReadDir(10)
		for _, de := range des {
			name := de.Name()
			if strings.HasSuffix(name, partialSuffix) {
				continue
			}
			if de.Type().IsRegular() {
				fi, err := de.Info()
				if err != nil {
					continue
				}
				ret = append(ret, WaitingFile{
					Name: filepath.Base(name),
					Size: fi.Size(),
				})
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func (s *peerAPIServer) DeleteFile(baseName string) error {
	if s.rootDir == "" {
		return errors.New("peerapi disabled; no storage configured")
	}
	if s.directFileMode {
		return errors.New("deletes not allowed in direct mode")
	}
	path, ok := s.diskPath(baseName)
	if !ok {
		return errors.New("bad filename")
	}
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *peerAPIServer) OpenFile(baseName string) (rc io.ReadCloser, size int64, err error) {
	if s.rootDir == "" {
		return nil, 0, errors.New("peerapi disabled; no storage configured")
	}
	if s.directFileMode {
		return nil, 0, errors.New("opens not allowed in direct mode")
	}
	path, ok := s.diskPath(baseName)
	if !ok {
		return nil, 0, errors.New("bad filename")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

func (s *peerAPIServer) listen(ip netaddr.IP, ifState *interfaces.State) (ln net.Listener, err error) {
	ipStr := ip.String()

	var lc net.ListenConfig
	if initListenConfig != nil {
		// On iOS/macOS, this sets the lc.Control hook to
		// setsockopt the interface index to bind to, to get
		// out of the network sandbox.
		if err := initListenConfig(&lc, ip, ifState, s.tunName); err != nil {
			return nil, err
		}
		if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
			ipStr = ""
		}
	}

	if wgengine.IsNetstack(s.b.e) {
		ipStr = ""
	}

	tcp4or6 := "tcp4"
	if ip.Is6() {
		tcp4or6 = "tcp6"
	}

	// Make a best effort to pick a deterministic port number for
	// the ip The lower three bytes are the same for IPv4 and IPv6
	// Tailscale addresses (at least currently), so we'll usually
	// get the same port number on both address families for
	// dev/debugging purposes, which is nice. But it's not so
	// deterministic that people will bake this into clients.
	// We try a few times just in case something's already
	// listening on that port (on all interfaces, probably).
	for try := uint8(0); try < 5; try++ {
		a16 := ip.As16()
		hashData := a16[len(a16)-3:]
		hashData[0] += try
		tryPort := (32 << 10) | uint16(crc32.ChecksumIEEE(hashData))
		ln, err = lc.Listen(context.Background(), tcp4or6, net.JoinHostPort(ipStr, strconv.Itoa(int(tryPort))))
		if err == nil {
			return ln, nil
		}
	}
	// Fall back to random ephemeral port.
	return lc.Listen(context.Background(), tcp4or6, net.JoinHostPort(ipStr, "0"))
}

type peerAPIListener struct {
	ps *peerAPIServer
	ip netaddr.IP
	lb *LocalBackend

	// ln is the Listener. It can be nil in netstack mode if there are more than
	// 1 local addresses (e.g. both an IPv4 and IPv6). When it's nil, port
	// and urlStr are still populated.
	ln net.Listener

	// urlStr is the base URL to access the peer API (http://ip:port/).
	urlStr string
	// port is just the port of urlStr.
	port int
}

func (pln *peerAPIListener) Close() error {
	if pln.ln != nil {
		return pln.ln.Close()
	}
	return nil
}

func (pln *peerAPIListener) serve() {
	if pln.ln == nil {
		return
	}
	defer pln.ln.Close()
	logf := pln.lb.logf
	for {
		c, err := pln.ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			logf("peerapi.Accept: %v", err)
			return
		}
		ta, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok {
			c.Close()
			logf("peerapi: unexpected RemoteAddr %#v", c.RemoteAddr())
			continue
		}
		ipp, ok := netaddr.FromStdAddr(ta.IP, ta.Port, "")
		if !ok {
			logf("peerapi: bogus TCPAddr %#v", ta)
			c.Close()
			continue
		}
		peerNode, peerUser, ok := pln.lb.WhoIs(ipp)
		if !ok {
			logf("peerapi: unknown peer %v", ipp)
			c.Close()
			continue
		}
		h := &peerAPIHandler{
			ps:         pln.ps,
			isSelf:     pln.ps.selfNode.User == peerNode.User,
			remoteAddr: ipp,
			peerNode:   peerNode,
			peerUser:   peerUser,
			lb:         pln.lb,
		}
		httpServer := &http.Server{
			Handler: h,
		}
		go httpServer.Serve(&oneConnListener{Listener: pln.ln, conn: c})
	}
}

type oneConnListener struct {
	net.Listener
	conn net.Conn
}

func (l *oneConnListener) Accept() (c net.Conn, err error) {
	c = l.conn
	if c == nil {
		err = io.EOF
		return
	}
	err = nil
	l.conn = nil
	return
}

func (l *oneConnListener) Close() error { return nil }

// peerAPIHandler serves the Peer API for a source specific client.
type peerAPIHandler struct {
	ps         *peerAPIServer
	remoteAddr netaddr.IPPort
	isSelf     bool                // whether peerNode is owned by same user as this node
	peerNode   *tailcfg.Node       // peerNode is who's making the request
	peerUser   tailcfg.UserProfile // profile of peerNode
	lb         *LocalBackend
}

func (h *peerAPIHandler) logf(format string, a ...interface{}) {
	h.ps.b.logf("peerapi: "+format, a...)
}

func (h *peerAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/v0/put/") {
		h.put(w, r)
		return
	}
	who := h.peerUser.DisplayName
	fmt.Fprintf(w, `<html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<body>
<h1>Hello, %s (%v)</h1>
This is my Tailscale device. Your device is %v.
`, html.EscapeString(who), h.remoteAddr.IP, html.EscapeString(h.peerNode.ComputedName))

	if h.isSelf {
		fmt.Fprintf(w, "<p>You are the owner of this node.\n")
	}
}

type incomingFile struct {
	name    string // "foo.jpg"
	started time.Time
	size    int64     // or -1 if unknown; never 0
	w       io.Writer // underlying writer
	ph      *peerAPIHandler

	mu         sync.Mutex
	copied     int64
	lastNotify time.Time
	finalPath  string // non-empty in direct mode, when file is done
}

func (f *incomingFile) markAndNotifyDone(finalPath string) {
	f.mu.Lock()
	f.finalPath = finalPath
	f.mu.Unlock()
	b := f.ph.ps.b
	b.sendFileNotify()
}

func (f *incomingFile) Write(p []byte) (n int, err error) {
	n, err = f.w.Write(p)

	b := f.ph.ps.b
	var needNotify bool
	defer func() {
		if needNotify {
			b.sendFileNotify()
		}
	}()
	if n > 0 {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.copied += int64(n)
		now := time.Now()
		if f.lastNotify.IsZero() || now.Sub(f.lastNotify) > time.Second {
			f.lastNotify = now
			needNotify = true
		}
	}
	return n, err
}

func (f *incomingFile) PartialFile() ipn.PartialFile {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ipn.PartialFile{
		Name:         f.name,
		Started:      f.started,
		DeclaredSize: f.size,
		Received:     f.copied,
		FinalPath:    f.finalPath,
	}
}

func (h *peerAPIHandler) put(w http.ResponseWriter, r *http.Request) {
	if !h.isSelf {
		http.Error(w, "not owner", http.StatusForbidden)
		return
	}
	if r.Method != "PUT" {
		http.Error(w, "not method PUT", http.StatusMethodNotAllowed)
		return
	}
	if h.ps.rootDir == "" {
		http.Error(w, "no rootdir", http.StatusInternalServerError)
		return
	}
	baseName := path.Base(r.URL.Path)
	dstFile, ok := h.ps.diskPath(baseName)
	if !ok {
		http.Error(w, "bad filename", 400)
		return
	}
	if h.ps.directFileMode {
		dstFile += partialSuffix
	}
	f, err := os.Create(dstFile)
	if err != nil {
		h.logf("put Create error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var success bool
	defer func() {
		if !success {
			os.Remove(dstFile)
		}
	}()
	var finalSize int64
	var inFile *incomingFile
	if r.ContentLength != 0 {
		inFile = &incomingFile{
			name:    baseName,
			started: time.Now(),
			size:    r.ContentLength,
			w:       f,
			ph:      h,
		}
		h.ps.b.registerIncomingFile(inFile, true)
		defer h.ps.b.registerIncomingFile(inFile, false)
		n, err := io.Copy(inFile, r.Body)
		if err != nil {
			f.Close()
			h.logf("put Copy error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		finalSize = n
	}
	if err := f.Close(); err != nil {
		h.logf("put Close error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.ps.directFileMode {
		finalPath := strings.TrimSuffix(dstFile, partialSuffix)
		if err := os.Rename(dstFile, finalPath); err != nil {
			h.logf("Rename error: %v", err)
			http.Error(w, "error renaming file", http.StatusInternalServerError)
			return
		}
		if inFile != nil { // non-zero length; TODO: notify even for zero length
			inFile.markAndNotifyDone(finalPath)
		}
	}

	h.logf("put of %s from %v/%v", baseName, approxSize(finalSize), h.remoteAddr.IP, h.peerNode.ComputedName)

	// TODO: set modtime
	// TODO: some real response
	success = true
	io.WriteString(w, "{}\n")
	h.ps.knownEmpty.Set(false)
	h.ps.b.sendFileNotify()
}

func approxSize(n int64) string {
	if n <= 1<<10 {
		return "<=1KB"
	}
	if n <= 1<<20 {
		return "<=1MB"
	}
	return fmt.Sprintf("~%dMB", n/1<<20)
}
