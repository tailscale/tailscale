// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package integration contains Tailscale integration tests.
//
// This package is considered internal and the public API is subject
// to change without notice.
package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/client/local"
	"tailscale.com/derp/derpserver"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/safesocket"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/nettype"
	"tailscale.com/util/rands"
	"tailscale.com/util/zstdframe"
	"tailscale.com/version"
)

var (
	verboseTailscaled = flag.Bool("verbose-tailscaled", false, "verbose tailscaled logging")
	verboseTailscale  = flag.Bool("verbose-tailscale", false, "verbose tailscale CLI logging")
)

// MainError is an error that's set if an error conditions happens outside of a
// context where a testing.TB is available. The caller can check it in its TestMain
// as a last ditch place to report errors.
var MainError syncs.AtomicValue[error]

// Binaries contains the paths to the tailscale and tailscaled binaries.
type Binaries struct {
	Dir        string
	Tailscale  BinaryInfo
	Tailscaled BinaryInfo
}

// BinaryInfo describes a tailscale or tailscaled binary.
type BinaryInfo struct {
	Path string // abs path to tailscale or tailscaled binary
	Size int64

	// FD and FDmu are set on Unix to efficiently copy the binary to a new
	// test's automatically-cleaned-up temp directory.
	FD   *os.File // for Unix (macOS, Linux, ...)
	FDMu sync.Locker

	// Contents is used on Windows instead of FD to copy the binary between
	// test directories. (On Windows you can't keep an FD open while an earlier
	// test's temp directories are deleted.)
	// This burns some memory and costs more in I/O, but oh well.
	Contents []byte
}

func (b BinaryInfo) CopyTo(dir string) (BinaryInfo, error) {
	ret := b
	ret.Path = filepath.Join(dir, path.Base(b.Path))

	switch runtime.GOOS {
	case "linux":
		// TODO(bradfitz): be fancy and use linkat with AT_EMPTY_PATH to avoid
		// copying? I couldn't get it to work, though.
		// For now, just do the same thing as every other Unix and copy
		// the binary.
		fallthrough
	case "darwin", "freebsd", "openbsd", "netbsd":
		f, err := os.OpenFile(ret.Path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o755)
		if err != nil {
			return BinaryInfo{}, err
		}
		b.FDMu.Lock()
		b.FD.Seek(0, 0)
		size, err := io.Copy(f, b.FD)
		b.FDMu.Unlock()
		if err != nil {
			f.Close()
			return BinaryInfo{}, fmt.Errorf("copying %q: %w", b.Path, err)
		}
		if size != b.Size {
			f.Close()
			return BinaryInfo{}, fmt.Errorf("copy %q: size mismatch: %d != %d", b.Path, size, b.Size)
		}
		if err := f.Close(); err != nil {
			return BinaryInfo{}, err
		}
		return ret, nil
	case "windows":
		return ret, os.WriteFile(ret.Path, b.Contents, 0o755)
	default:
		return BinaryInfo{}, fmt.Errorf("unsupported OS %q", runtime.GOOS)
	}
}

// GetBinaries create a temp directory using tb and builds (or copies previously
// built) cmd/tailscale and cmd/tailscaled binaries into that directory.
//
// It fails tb if the build or binary copies fail.
func GetBinaries(tb testing.TB) *Binaries {
	dir := tb.TempDir()
	buildOnce.Do(func() {
		buildErr = buildTestBinaries(dir)
	})
	if buildErr != nil {
		tb.Fatal(buildErr)
	}
	if binariesCache.Dir == dir {
		return binariesCache
	}
	ts, err := binariesCache.Tailscale.CopyTo(dir)
	if err != nil {
		tb.Fatalf("copying tailscale binary: %v", err)
	}
	tsd, err := binariesCache.Tailscaled.CopyTo(dir)
	if err != nil {
		tb.Fatalf("copying tailscaled binary: %v", err)
	}
	return &Binaries{
		Dir:        dir,
		Tailscale:  ts,
		Tailscaled: tsd,
	}
}

var (
	buildOnce     sync.Once
	buildErr      error
	binariesCache *Binaries
)

// buildTestBinaries builds tailscale and tailscaled.
// On success, it initializes [binariesCache].
func buildTestBinaries(dir string) error {
	getBinaryInfo := func(name string) (BinaryInfo, error) {
		bi := BinaryInfo{Path: filepath.Join(dir, name+exe())}
		fi, err := os.Stat(bi.Path)
		if err != nil {
			return BinaryInfo{}, fmt.Errorf("stat %q: %v", bi.Path, err)
		}
		bi.Size = fi.Size()

		switch runtime.GOOS {
		case "windows":
			bi.Contents, err = os.ReadFile(bi.Path)
			if err != nil {
				return BinaryInfo{}, fmt.Errorf("read %q: %v", bi.Path, err)
			}
		default:
			bi.FD, err = os.OpenFile(bi.Path, os.O_RDONLY, 0)
			if err != nil {
				return BinaryInfo{}, fmt.Errorf("open %q: %v", bi.Path, err)
			}
			bi.FDMu = new(sync.Mutex)
			// Note: bi.FD is copied around between tests but never closed, by
			// design. It will be closed when the process exits, and that will
			// close the inode that we're copying the bytes from for each test.
		}
		return bi, nil
	}
	err := build(dir, "tailscale.com/cmd/tailscaled", "tailscale.com/cmd/tailscale")
	if err != nil {
		return err
	}
	b := &Binaries{
		Dir: dir,
	}
	b.Tailscale, err = getBinaryInfo("tailscale")
	if err != nil {
		return err
	}
	b.Tailscaled, err = getBinaryInfo("tailscaled")
	if err != nil {
		return err
	}
	binariesCache = b
	return nil
}

func build(outDir string, targets ...string) error {
	goBin, err := findGo()
	if err != nil {
		return err
	}
	cmd := exec.Command(goBin, "install")
	if version.IsRace() {
		cmd.Args = append(cmd.Args, "-race")
	}
	cmd.Args = append(cmd.Args, targets...)
	cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH, "GOBIN="+outDir)
	errOut, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if strings.Contains(string(errOut), "when GOBIN is set") {
		// Fallback slow path for cross-compiled binaries.
		for _, target := range targets {
			outFile := filepath.Join(outDir, path.Base(target)+exe())
			cmd := exec.Command(goBin, "build", "-o", outFile)
			if version.IsRace() {
				cmd.Args = append(cmd.Args, "-race")
			}
			cmd.Args = append(cmd.Args, target)
			cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH)
			if errOut, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to build %v with %v: %v, %s", target, goBin, err, errOut)
			}
		}
		return nil
	}
	return fmt.Errorf("failed to build %v with %v: %v, %s", targets, goBin, err, errOut)
}

func findGo() (string, error) {
	// Go 1.19 attempted to be helpful by prepending $PATH with GOROOT/bin based
	// on the executed go binary when invoked using `go test` or `go generate`,
	// however, this doesn't cover cases when run otherwise, such as via `go run`.
	// runtime.GOROOT() may often be empty these days, so the safe thing to do
	// here is, in order:
	// 1. Look for a go binary in $PATH[0].
	// 2. Look for a go binary in runtime.GOROOT()/bin if runtime.GOROOT() is non-empty.
	// 3. Look for a go binary in $PATH.

	// For tests we want to run as root on GitHub actions, we run with -exec=sudo,
	// but that results in this test running with a different PATH and picking the
	// wrong Go. So hard code the GitHub Actions case.
	if os.Getuid() == 0 && os.Getenv("GITHUB_ACTIONS") == "true" {
		const sudoGithubGo = "/home/runner/.cache/tailscale-go/bin/go"
		if _, err := os.Stat(sudoGithubGo); err == nil {
			return sudoGithubGo, nil
		}
	}

	paths := strings.FieldsFunc(os.Getenv("PATH"), func(r rune) bool { return os.IsPathSeparator(uint8(r)) })
	if len(paths) > 0 {
		candidate := filepath.Join(paths[0], "go"+exe())
		if path, err := exec.LookPath(candidate); err == nil {
			return path, err
		}
	}

	if runtime.GOROOT() != "" {
		candidate := filepath.Join(runtime.GOROOT(), "bin", "go"+exe())
		if path, err := exec.LookPath(candidate); err == nil {
			return path, err
		}
	}

	return exec.LookPath("go")
}

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// RunDERPAndSTUN runs a local DERP and STUN server for tests, returning the derpMap
// that clients should use. This creates resources that must be cleaned up with the
// returned cleanup function.
func RunDERPAndSTUN(t testing.TB, logf logger.Logf, ipAddress string) (derpMap *tailcfg.DERPMap) {
	t.Helper()

	d := derpserver.New(key.NewNode(), logf)

	ln, err := net.Listen("tcp", net.JoinHostPort(ipAddress, "0"))
	if err != nil {
		t.Fatal(err)
	}

	httpsrv := httptest.NewUnstartedServer(derpserver.Handler(d))
	httpsrv.Listener.Close()
	httpsrv.Listener = ln
	httpsrv.Config.ErrorLog = logger.StdLogger(logf)
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()

	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})

	m := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:             "t1",
						RegionID:         1,
						HostName:         ipAddress,
						IPv4:             ipAddress,
						IPv6:             "none",
						STUNPort:         stunAddr.Port,
						DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
						InsecureForTests: true,
						STUNTestIP:       ipAddress,
					},
				},
			},
		},
	}

	t.Logf("DERP httpsrv listener: %v", httpsrv.Listener.Addr())

	t.Cleanup(func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		d.Close()
		stunCleanup()
		ln.Close()
	})

	return m
}

// LogCatcher is a minimal logcatcher for the logtail upload client.
type LogCatcher struct {
	mu     sync.Mutex
	logf   logger.Logf
	buf    bytes.Buffer
	gotErr error
	reqs   int
	raw    bool // indicates whether to store the raw JSON logs uploaded, instead of just the text
}

// UseLogf makes the logcatcher implementation use a given logf function
// to dump all logs to.
func (lc *LogCatcher) UseLogf(fn logger.Logf) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.logf = fn
}

// StoreRawJSON instructs lc to save the raw JSON uploads, rather than just the text.
func (lc *LogCatcher) StoreRawJSON() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.raw = true
}

func (lc *LogCatcher) logsContains(sub mem.RO) bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return mem.Contains(mem.B(lc.buf.Bytes()), sub)
}

func (lc *LogCatcher) numRequests() int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.reqs
}

func (lc *LogCatcher) logsString() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.buf.String()
}

// Reset clears the buffered logs from memory.
func (lc *LogCatcher) Reset() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.buf.Reset()
}

func (lc *LogCatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// POST /c/<collection-name>/<private-ID>
	if r.Method != "POST" {
		log.Printf("bad logcatcher method: %v", r.Method)
		http.Error(w, "only POST is supported", 400)
		return
	}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/c/"), "/")
	if len(pathParts) != 2 {
		log.Printf("bad logcatcher path: %q", r.URL.Path)
		http.Error(w, "bad URL", 400)
		return
	}
	// collectionName := pathPaths[0]
	privID, err := logid.ParsePrivateID(pathParts[1])
	if err != nil {
		log.Printf("bad log ID: %q: %v", r.URL.Path, err)
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("http.Request.Body.Read: %v", err)
		return
	}
	if r.Header.Get("Content-Encoding") == "zstd" {
		bodyBytes, err = zstdframe.AppendDecode(nil, bodyBytes)
		if err != nil {
			log.Printf("zstdframe.AppendDecode: %v", err)
			http.Error(w, err.Error(), 400)
			return
		}
	}

	type Entry struct {
		Logtail struct {
			ClientTime time.Time `json:"client_time"`
			ServerTime time.Time `json:"server_time"`
			Error      struct {
				BadData string `json:"bad_data"`
			} `json:"error"`
		} `json:"logtail"`
		Text string `json:"text"`
	}
	var jreq []Entry
	if len(bodyBytes) > 0 && bodyBytes[0] == '[' {
		err = json.Unmarshal(bodyBytes, &jreq)
	} else {
		var ent Entry
		err = json.Unmarshal(bodyBytes, &ent)
		jreq = append(jreq, ent)
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.reqs++
	if lc.gotErr == nil && err != nil {
		lc.gotErr = err
	}
	if err != nil {
		fmt.Fprintf(&lc.buf, "error from %s of %#q: %v\n", r.Method, bodyBytes, err)
		if lc.logf != nil {
			lc.logf("error from %s of %#q: %v\n", r.Method, bodyBytes, err)
		}
	} else {
		id := privID.Public().String()[:3] // good enough for integration tests
		for _, ent := range jreq {
			if lc.raw {
				lc.buf.Write(bodyBytes)
				continue
			}
			fmt.Fprintf(&lc.buf, "%s\n", strings.TrimSpace(ent.Text))
			if lc.logf != nil {
				lc.logf("logcatch:%s: %s", id, strings.TrimSpace(ent.Text))
			}
		}
	}
	w.WriteHeader(200) // must have no content, but not a 204
}

// TestEnv contains the test environment (set of servers) used by one
// or more nodes.
type TestEnv struct {
	t                      testing.TB
	tunMode                bool
	cli                    string
	daemon                 string
	loopbackPort           *int
	neverDirectUDP         bool
	relayServerUseLoopback bool

	LogCatcher       *LogCatcher
	LogCatcherServer *httptest.Server

	Control       *testcontrol.Server
	ControlServer *httptest.Server

	TrafficTrap       *trafficTrap
	TrafficTrapServer *httptest.Server
}

// ControlURL returns e.ControlServer.URL, panicking if it's the empty string,
// which it should never be in tests.
func (e *TestEnv) ControlURL() string {
	s := e.ControlServer.URL
	if s == "" {
		panic("control server not set")
	}
	return s
}

// TestEnvOpt represents an option that can be passed to NewTestEnv.
type TestEnvOpt interface {
	ModifyTestEnv(*TestEnv)
}

// ConfigureControl is a test option that configures the test control server.
type ConfigureControl func(*testcontrol.Server)

func (f ConfigureControl) ModifyTestEnv(te *TestEnv) {
	f(te.Control)
}

// NewTestEnv starts a bunch of services and returns a new test environment.
// NewTestEnv arranges for the environment's resources to be cleaned up on exit.
func NewTestEnv(t testing.TB, opts ...TestEnvOpt) *TestEnv {
	if runtime.GOOS == "windows" {
		t.Skip("not tested/working on Windows yet")
	}
	derpMap := RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	logc := new(LogCatcher)
	control := &testcontrol.Server{
		Logf:    logger.WithPrefix(t.Logf, "testcontrol: "),
		DERPMap: derpMap,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	trafficTrap := new(trafficTrap)
	binaries := GetBinaries(t)
	e := &TestEnv{
		t:                 t,
		cli:               binaries.Tailscale.Path,
		daemon:            binaries.Tailscaled.Path,
		LogCatcher:        logc,
		LogCatcherServer:  httptest.NewServer(logc),
		Control:           control,
		ControlServer:     control.HTTPTestServer,
		TrafficTrap:       trafficTrap,
		TrafficTrapServer: httptest.NewServer(trafficTrap),
	}
	for _, o := range opts {
		o.ModifyTestEnv(e)
	}
	control.HTTPTestServer.Start()
	t.Cleanup(func() {
		// Shut down e.
		if err := e.TrafficTrap.Err(); err != nil {
			e.t.Errorf("traffic trap: %v", err)
			e.t.Logf("logs: %s", e.LogCatcher.logsString())
		}
		e.LogCatcherServer.Close()
		e.TrafficTrapServer.Close()
		e.ControlServer.Close()
	})
	t.Logf("control URL: %v", e.ControlURL())
	return e
}

// TestNode is a machine with a tailscale & tailscaled.
// Currently, the test is simplistic and user==node==machine.
// That may grow complexity later to test more.
type TestNode struct {
	env              *TestEnv
	tailscaledParser *nodeOutputParser

	dir          string // temp dir for sock & state
	configFile   string // or empty for none
	sockFile     string
	stateFile    string
	upFlagGOOS   string // if non-empty, sets TS_DEBUG_UP_FLAG_GOOS for cmd/tailscale CLI
	encryptState bool

	mu        sync.Mutex
	onLogLine []func([]byte)
	lc        *local.Client
}

// NewTestNode allocates a temp directory for a new test node.
// The node is not started automatically.
func NewTestNode(t *testing.T, env *TestEnv) *TestNode {
	dir := t.TempDir()
	sockFile := filepath.Join(dir, "tailscale.sock")
	if len(sockFile) >= 104 {
		// Maximum length for a unix socket on darwin. Try something else.
		sockFile = filepath.Join(os.TempDir(), rands.HexString(8)+".sock")
		t.Cleanup(func() { os.Remove(sockFile) })
	}
	n := &TestNode{
		env:       env,
		dir:       dir,
		sockFile:  sockFile,
		stateFile: filepath.Join(dir, "tailscaled.state"), // matches what cmd/tailscaled uses
	}

	// Look for a data race or panic.
	// Once we see the start marker, start logging the rest.
	var sawRace bool
	var sawPanic bool
	n.addLogLineHook(func(line []byte) {
		lineB := mem.B(line)
		if mem.Contains(lineB, mem.S("DEBUG-ADDR=")) {
			t.Log(strings.TrimSpace(string(line)))
		}
		if mem.Contains(lineB, mem.S("WARNING: DATA RACE")) {
			sawRace = true
		}
		if mem.HasPrefix(lineB, mem.S("panic: ")) {
			sawPanic = true
		}
		if sawRace || sawPanic {
			t.Logf("%s", line)
		}
	})

	return n
}

func (n *TestNode) LocalClient() *local.Client {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.lc == nil {
		tr := &http.Transport{}
		n.lc = &local.Client{
			Socket:        n.sockFile,
			UseSocketOnly: true,
		}
		n.env.t.Cleanup(tr.CloseIdleConnections)
	}
	return n.lc
}

func (n *TestNode) diskPrefs() *ipn.Prefs {
	t := n.env.t
	t.Helper()
	if _, err := os.ReadFile(n.stateFile); err != nil {
		t.Fatalf("reading prefs: %v", err)
	}
	fs, err := store.New(nil, n.stateFile)
	if err != nil {
		t.Fatalf("reading prefs, NewFileStore: %v", err)
	}
	p, err := ipnlocal.ReadStartupPrefsForTest(t.Logf, fs)
	if err != nil {
		t.Fatalf("reading prefs, ReadDiskPrefsForTest: %v", err)
	}
	return p.AsStruct()
}

// AwaitResponding waits for n's tailscaled to be up enough to be
// responding, but doesn't wait for any particular state.
func (n *TestNode) AwaitResponding() {
	t := n.env.t
	t.Helper()
	n.AwaitListening()

	st := n.MustStatus()
	t.Logf("Status: %s", st.BackendState)

	if err := tstest.WaitFor(20*time.Second, func() error {
		const sub = `Program starting: `
		if !n.env.LogCatcher.logsContains(mem.S(sub)) {
			return fmt.Errorf("log catcher didn't see %#q; got %s", sub, n.env.LogCatcher.logsString())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// addLogLineHook registers a hook f to be called on each tailscaled
// log line output.
func (n *TestNode) addLogLineHook(f func([]byte)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onLogLine = append(n.onLogLine, f)
}

// socks5AddrChan returns a channel that receives the address (e.g. "localhost:23874")
// of the node's SOCKS5 listener, once started.
func (n *TestNode) socks5AddrChan() <-chan string {
	ch := make(chan string, 1)
	n.addLogLineHook(func(line []byte) {
		const sub = "SOCKS5 listening on "
		i := mem.Index(mem.B(line), mem.S(sub))
		if i == -1 {
			return
		}
		addr := strings.TrimSpace(string(line)[i+len(sub):])
		select {
		case ch <- addr:
		default:
		}
	})
	return ch
}

func (n *TestNode) AwaitSocksAddr(ch <-chan string) string {
	t := n.env.t
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case v := <-ch:
		return v
	case <-timer.C:
		t.Fatal("timeout waiting for node to log its SOCK5 listening address")
		panic("unreachable")
	}
}

// nodeOutputParser parses stderr of tailscaled processes, calling the
// per-line callbacks previously registered via
// testNode.addLogLineHook.
type nodeOutputParser struct {
	allBuf      bytes.Buffer
	pendLineBuf bytes.Buffer
	n           *TestNode
}

func (op *nodeOutputParser) Write(p []byte) (n int, err error) {
	tn := op.n
	tn.mu.Lock()
	defer tn.mu.Unlock()

	op.allBuf.Write(p)
	n, err = op.pendLineBuf.Write(p)
	op.parseLinesLocked()
	return
}

func (op *nodeOutputParser) parseLinesLocked() {
	n := op.n
	buf := op.pendLineBuf.Bytes()
	for len(buf) > 0 {
		nl := bytes.IndexByte(buf, '\n')
		if nl == -1 {
			break
		}
		line := buf[:nl+1]
		buf = buf[nl+1:]

		for _, f := range n.onLogLine {
			f(line)
		}
	}
	if len(buf) == 0 {
		op.pendLineBuf.Reset()
	} else {
		io.CopyN(io.Discard, &op.pendLineBuf, int64(op.pendLineBuf.Len()-len(buf)))
	}
}

type Daemon struct {
	Process *os.Process
}

func (d *Daemon) MustCleanShutdown(t testing.TB) {
	d.Process.Signal(os.Interrupt)
	ps, err := d.Process.Wait()
	if err != nil {
		t.Fatalf("tailscaled Wait: %v", err)
	}
	if ps.ExitCode() != 0 {
		t.Errorf("tailscaled ExitCode = %d; want 0", ps.ExitCode())
	}
}

// awaitTailscaledRunnable tries to run `tailscaled --version` until it
// works. This is an unsatisfying workaround for ETXTBSY we were seeing
// on GitHub Actions that aren't understood. It's not clear what's holding
// a writable fd to tailscaled after `go install` completes.
// See https://github.com/tailscale/tailscale/issues/15868.
func (n *TestNode) awaitTailscaledRunnable() error {
	t := n.env.t
	t.Helper()
	if err := tstest.WaitFor(10*time.Second, func() error {
		out, err := exec.Command(n.env.daemon, "--version").CombinedOutput()
		if err == nil {
			return nil
		}
		t.Logf("error running tailscaled --version: %v, %s", err, out)
		return err
	}); err != nil {
		return fmt.Errorf("gave up trying to run tailscaled: %v", err)
	}
	return nil
}

// StartDaemon starts the node's tailscaled, failing if it fails to start.
// StartDaemon ensures that the process will exit when the test completes.
func (n *TestNode) StartDaemon() *Daemon {
	return n.StartDaemonAsIPNGOOS(runtime.GOOS)
}

func (n *TestNode) StartDaemonAsIPNGOOS(ipnGOOS string) *Daemon {
	t := n.env.t

	if err := n.awaitTailscaledRunnable(); err != nil {
		t.Fatalf("awaitTailscaledRunnable: %v", err)
	}

	cmd := exec.Command(n.env.daemon)
	cmd.Args = append(cmd.Args,
		"--statedir="+n.dir,
		"--socket="+n.sockFile,
		"--socks5-server=localhost:0",
		"--debug=localhost:0",
	)
	if *verboseTailscaled {
		cmd.Args = append(cmd.Args, "-verbose=2")
	}
	if !n.env.tunMode {
		cmd.Args = append(cmd.Args,
			"--tun=userspace-networking",
		)
	}
	if n.configFile != "" {
		cmd.Args = append(cmd.Args, "--config="+n.configFile)
	}
	if n.encryptState {
		cmd.Args = append(cmd.Args, "--encrypt-state")
	}
	cmd.Env = append(os.Environ(),
		"TS_DEBUG_PERMIT_HTTP_C2N=1",
		"TS_LOG_TARGET="+n.env.LogCatcherServer.URL,
		"HTTP_PROXY="+n.env.TrafficTrapServer.URL,
		"HTTPS_PROXY="+n.env.TrafficTrapServer.URL,
		"TS_DEBUG_FAKE_GOOS="+ipnGOOS,
		"TS_LOGS_DIR="+t.TempDir(),
		"TS_NETCHECK_GENERATE_204_URL="+n.env.ControlServer.URL+"/generate_204",
		"TS_ASSUME_NETWORK_UP_FOR_TEST=1", // don't pause control client in airplane mode (no wifi, etc)
		"TS_PANIC_IF_HIT_MAIN_CONTROL=1",
		"TS_DISABLE_PORTMAPPER=1", // shouldn't be needed; test is all localhost
		"TS_DEBUG_LOG_RATE=all",
	)
	if n.env.loopbackPort != nil {
		cmd.Env = append(cmd.Env, "TS_DEBUG_NETSTACK_LOOPBACK_PORT="+strconv.Itoa(*n.env.loopbackPort))
	}
	if n.env.neverDirectUDP {
		cmd.Env = append(cmd.Env, "TS_DEBUG_NEVER_DIRECT_UDP=1")
	}
	if n.env.relayServerUseLoopback {
		cmd.Env = append(cmd.Env, "TS_DEBUG_RELAY_SERVER_ADDRS=::1,127.0.0.1")
	}
	if version.IsRace() {
		cmd.Env = append(cmd.Env, "GORACE=halt_on_error=1")
	}
	n.tailscaledParser = &nodeOutputParser{n: n}
	cmd.Stderr = n.tailscaledParser
	if *verboseTailscaled {
		cmd.Stdout = os.Stdout
		cmd.Stderr = io.MultiWriter(cmd.Stderr, os.Stderr)
	}
	if runtime.GOOS != "windows" {
		pr, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pw.Close() })
		cmd.ExtraFiles = append(cmd.ExtraFiles, pr)
		cmd.Env = append(cmd.Env, "TS_PARENT_DEATH_FD=3")
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting tailscaled: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	return &Daemon{
		Process: cmd.Process,
	}
}

func (n *TestNode) MustUp(extraArgs ...string) {
	t := n.env.t
	t.Helper()
	args := []string{
		"up",
		"--login-server=" + n.env.ControlURL(),
		"--reset",
	}
	args = append(args, extraArgs...)
	cmd := n.Tailscale(args...)
	t.Logf("Running %v ...", cmd)
	cmd.Stdout = nil // in case --verbose-tailscale was set
	cmd.Stderr = nil // in case --verbose-tailscale was set
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("up: %v, %v", string(b), err)
	}
}

func (n *TestNode) MustDown() {
	t := n.env.t
	t.Logf("Running down ...")
	if err := n.Tailscale("down", "--accept-risk=all").Run(); err != nil {
		t.Fatalf("down: %v", err)
	}
}

func (n *TestNode) MustLogOut() {
	t := n.env.t
	t.Logf("Running logout ...")
	if err := n.Tailscale("logout").Run(); err != nil {
		t.Fatalf("logout: %v", err)
	}
}

func (n *TestNode) Ping(otherNode *TestNode) error {
	t := n.env.t
	ip := otherNode.AwaitIP4().String()
	t.Logf("Running ping %v (from %v)...", ip, n.AwaitIP4())
	return n.Tailscale("ping", ip).Run()
}

// AwaitListening waits for the tailscaled to be serving local clients
// over its localhost IPC mechanism. (Unix socket, etc)
func (n *TestNode) AwaitListening() {
	t := n.env.t
	if err := tstest.WaitFor(20*time.Second, func() (err error) {
		c, err := safesocket.ConnectContext(context.Background(), n.sockFile)
		if err == nil {
			c.Close()
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (n *TestNode) AwaitIPs() []netip.Addr {
	t := n.env.t
	t.Helper()
	var addrs []netip.Addr
	if err := tstest.WaitFor(20*time.Second, func() error {
		cmd := n.Tailscale("ip")
		cmd.Stdout = nil // in case --verbose-tailscale was set
		cmd.Stderr = nil // in case --verbose-tailscale was set
		out, err := cmd.Output()
		if err != nil {
			return err
		}
		ips := string(out)
		ipslice := strings.Fields(ips)
		addrs = make([]netip.Addr, len(ipslice))

		for i, ip := range ipslice {
			netIP, err := netip.ParseAddr(ip)
			if err != nil {
				t.Fatal(err)
			}
			addrs[i] = netIP
		}
		return nil
	}); err != nil {
		t.Fatalf("awaiting an IP address: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatalf("returned IP address was blank")
	}
	return addrs
}

// AwaitIP4 returns the IPv4 address of n.
func (n *TestNode) AwaitIP4() netip.Addr {
	t := n.env.t
	t.Helper()
	ips := n.AwaitIPs()
	return ips[0]
}

// AwaitIP6 returns the IPv6 address of n.
func (n *TestNode) AwaitIP6() netip.Addr {
	t := n.env.t
	t.Helper()
	ips := n.AwaitIPs()
	return ips[1]
}

// AwaitRunning waits for n to reach the IPN state "Running".
func (n *TestNode) AwaitRunning() {
	t := n.env.t
	t.Helper()
	n.AwaitBackendState("Running")
}

func (n *TestNode) AwaitBackendState(state string) {
	t := n.env.t
	t.Helper()
	if err := tstest.WaitFor(20*time.Second, func() error {
		st, err := n.Status()
		if err != nil {
			return err
		}
		if st.BackendState != state {
			return fmt.Errorf("in state %q; want %q", st.BackendState, state)
		}
		return nil
	}); err != nil {
		t.Fatalf("failure/timeout waiting for transition to Running status: %v", err)
	}
}

// AwaitNeedsLogin waits for n to reach the IPN state "NeedsLogin".
func (n *TestNode) AwaitNeedsLogin() {
	t := n.env.t
	t.Helper()
	if err := tstest.WaitFor(20*time.Second, func() error {
		st, err := n.Status()
		if err != nil {
			return err
		}
		if st.BackendState != "NeedsLogin" {
			return fmt.Errorf("in state %q", st.BackendState)
		}
		return nil
	}); err != nil {
		t.Fatalf("failure/timeout waiting for transition to NeedsLogin status: %v", err)
	}
}

func (n *TestNode) TailscaleForOutput(arg ...string) *exec.Cmd {
	cmd := n.Tailscale(arg...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd
}

// Tailscale returns a command that runs the tailscale CLI with the provided arguments.
// It does not start the process.
func (n *TestNode) Tailscale(arg ...string) *exec.Cmd {
	cmd := exec.Command(n.env.cli)
	cmd.Args = append(cmd.Args, "--socket="+n.sockFile)
	cmd.Args = append(cmd.Args, arg...)
	cmd.Dir = n.dir
	cmd.Env = append(os.Environ(),
		"TS_DEBUG_UP_FLAG_GOOS="+n.upFlagGOOS,
		"TS_LOGS_DIR="+n.env.t.TempDir(),
	)
	if *verboseTailscale {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd
}

func (n *TestNode) Status() (*ipnstate.Status, error) {
	cmd := n.Tailscale("status", "--json")
	cmd.Stdout = nil // in case --verbose-tailscale was set
	cmd.Stderr = nil // in case --verbose-tailscale was set
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("running tailscale status: %v, %s", err, out)
	}
	st := new(ipnstate.Status)
	if err := json.Unmarshal(out, st); err != nil {
		return nil, fmt.Errorf("decoding tailscale status JSON: %w\njson:\n%s", err, out)
	}
	return st, nil
}

func (n *TestNode) MustStatus() *ipnstate.Status {
	tb := n.env.t
	tb.Helper()
	st, err := n.Status()
	if err != nil {
		tb.Fatal(err)
	}
	return st
}

// trafficTrap is an HTTP proxy handler to note whether any
// HTTP traffic tries to leave localhost from tailscaled. We don't
// expect any, so any request triggers a failure.
type trafficTrap struct {
	atomicErr syncs.AtomicValue[error]
}

func (tt *trafficTrap) Err() error {
	return tt.atomicErr.Load()
}

func (tt *trafficTrap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var got bytes.Buffer
	r.Write(&got)
	err := fmt.Errorf("unexpected HTTP request via proxy: %s", got.Bytes())
	MainError.Store(err)
	if tt.Err() == nil {
		// Best effort at remembering the first request.
		tt.atomicErr.Store(err)
	}
	log.Printf("Error: %v", err)
	w.WriteHeader(403)
}

type authURLParserWriter struct {
	buf bytes.Buffer
	fn  func(urlStr string) error
}

var authURLRx = regexp.MustCompile(`(https?://\S+/auth/\S+)`)

func (w *authURLParserWriter) Write(p []byte) (n int, err error) {
	n, err = w.buf.Write(p)
	m := authURLRx.FindSubmatch(w.buf.Bytes())
	if m != nil {
		urlStr := string(m[1])
		w.buf.Reset() // so it's not matched again
		if err := w.fn(urlStr); err != nil {
			return 0, err
		}
	}
	return n, err
}
