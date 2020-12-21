// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package logpolicy manages the creation or reuse of logtail loggers,
// caching collection instance state on disk for use on future runs of
// programs on the same machine.
package logpolicy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
	"tailscale.com/atomicfile"
	"tailscale.com/logtail"
	"tailscale.com/logtail/filch"
	"tailscale.com/net/netns"
	"tailscale.com/net/tlsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/paths"
	"tailscale.com/smallzstd"
	"tailscale.com/types/logger"
	"tailscale.com/util/racebuild"
	"tailscale.com/version"
)

// Config represents an instance of logs in a collection.
type Config struct {
	Collection string
	PrivateID  logtail.PrivateID
	PublicID   logtail.PublicID
}

// Policy is a logger and its public ID.
type Policy struct {
	// Logtail is the logger.
	Logtail *logtail.Logger
	// PublicID is the logger's instance identifier.
	PublicID logtail.PublicID
}

// ToBytes returns the JSON representation of c.
func (c *Config) ToBytes() []byte {
	data, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		log.Fatalf("logpolicy.Config marshal: %v", err)
	}
	return data
}

// Save writes the JSON representation of c to stateFile.
func (c *Config) save(stateFile string) error {
	c.PublicID = c.PrivateID.Public()
	if err := os.MkdirAll(filepath.Dir(stateFile), 0750); err != nil {
		return err
	}
	data := c.ToBytes()
	if err := atomicfile.WriteFile(stateFile, data, 0600); err != nil {
		return err
	}
	return nil
}

// ConfigFromBytes parses a a Config from its JSON encoding.
func ConfigFromBytes(jsonEnc []byte) (*Config, error) {
	c := &Config{}
	if err := json.Unmarshal(jsonEnc, c); err != nil {
		return nil, err
	}
	return c, nil
}

// stderrWriter is an io.Writer that always writes to the latest
// os.Stderr, even if os.Stderr changes during the lifetime of the
// stderrWriter value.
type stderrWriter struct{}

func (stderrWriter) Write(buf []byte) (int, error) {
	return os.Stderr.Write(buf)
}

type logWriter struct {
	logger *log.Logger
}

func (l logWriter) Write(buf []byte) (int, error) {
	l.logger.Printf("%s", buf)
	return len(buf), nil
}

// logsDir returns the directory to use for log configuration and
// buffer storage.
func logsDir(logf logger.Logf) string {
	// STATE_DIRECTORY is set by systemd 240+ but we support older
	// systems-d. For example, Ubuntu 18.04 (Bionic Beaver) is 237.
	systemdStateDir := os.Getenv("STATE_DIRECTORY")
	if systemdStateDir != "" {
		logf("logpolicy: using $STATE_DIRECTORY, %q", systemdStateDir)
		return systemdStateDir
	}

	// Default to e.g. /var/lib/tailscale or /var/db/tailscale on Unix.
	if d := paths.DefaultTailscaledStateFile(); d != "" {
		d = filepath.Dir(d) // directory of e.g. "/var/lib/tailscale/tailscaled.state"
		if err := os.MkdirAll(d, 0700); err == nil {
			logf("logpolicy: using system state directory %q", d)
			return d
		}
	}

	cacheDir, err := os.UserCacheDir()
	if err == nil {
		d := filepath.Join(cacheDir, "Tailscale")
		logf("logpolicy: using UserCacheDir, %q", d)
		return d
	}

	// Use the current working directory, unless we're being run by a
	// service manager that sets it to /.
	wd, err := os.Getwd()
	if err == nil && wd != "/" {
		logf("logpolicy: using current directory, %q", wd)
		return wd
	}

	// No idea where to put stuff. Try to create a temp dir. It'll
	// mean we might lose some logs and rotate through log IDs, but
	// it's something.
	tmp, err := ioutil.TempDir("", "tailscaled-log-*")
	if err != nil {
		panic("no safe place found to store log state")
	}
	logf("logpolicy: using temp directory, %q", tmp)
	return tmp
}

// runningUnderSystemd reports whether we're running under systemd.
func runningUnderSystemd() bool {
	if runtime.GOOS == "linux" && os.Getppid() == 1 {
		slurp, _ := ioutil.ReadFile("/proc/1/stat")
		return bytes.HasPrefix(slurp, []byte("1 (systemd) "))
	}
	return false
}

// tryFixLogStateLocation is a temporary fixup for
// https://github.com/tailscale/tailscale/issues/247 . We accidentally
// wrote logging state files to /, and then later to $CACHE_DIRECTORY
// (which is incorrect because the log ID is not reconstructible if
// deleted - it's state, not cache data).
//
// If log state for cmdname exists in / or $CACHE_DIRECTORY, and no
// log state for that command exists in dir, then the log state is
// moved from whereever it does exist, into dir. Leftover logs state
// in / and $CACHE_DIRECTORY is deleted.
func tryFixLogStateLocation(dir, cmdname string) {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		// These are the OSes where we might have written stuff into
		// root. Others use different logic to find the logs storage
		// dir.
	default:
		return
	}
	if cmdname == "" {
		log.Printf("[unexpected] no cmdname given to tryFixLogStateLocation, please file a bug at https://github.com/tailscale/tailscale")
		return
	}
	if dir == "/" {
		// Trying to store things in / still. That's a bug, but don't
		// abort hard.
		log.Printf("[unexpected] storing logging config in /, please file a bug at https://github.com/tailscale/tailscale")
		return
	}
	if os.Getuid() != 0 {
		// Only root could have written log configs to weird places.
		return
	}

	// We stored logs in 2 incorrect places: either /, or CACHE_DIR
	// (aka /var/cache/tailscale). We want to move files into the
	// provided dir, preferring those in CACHE_DIR over those in / if
	// both exist. If files already exist in dir, don't
	// overwrite. Finally, once we've maybe moved files around, we
	// want to delete leftovers in / and CACHE_DIR, to clean up after
	// our past selves.

	files := []string{
		fmt.Sprintf("%s.log.conf", cmdname),
		fmt.Sprintf("%s.log1.txt", cmdname),
		fmt.Sprintf("%s.log2.txt", cmdname),
	}

	// checks if any of the files above exist in d.
	checkExists := func(d string) (bool, error) {
		for _, file := range files {
			p := filepath.Join(d, file)
			_, err := os.Stat(p)
			if os.IsNotExist(err) {
				continue
			} else if err != nil {
				return false, fmt.Errorf("stat %q: %w", p, err)
			}
			return true, nil
		}
		return false, nil
	}
	// move files from d into dir, if they exist.
	moveFiles := func(d string) error {
		for _, file := range files {
			src := filepath.Join(d, file)
			_, err := os.Stat(src)
			if os.IsNotExist(err) {
				continue
			} else if err != nil {
				return fmt.Errorf("stat %q: %v", src, err)
			}
			dst := filepath.Join(dir, file)
			bs, err := exec.Command("mv", src, dst).CombinedOutput()
			if err != nil {
				return fmt.Errorf("mv %q %q: %v (%s)", src, dst, err, bs)
			}
		}
		return nil
	}

	existsInRoot, err := checkExists("/")
	if err != nil {
		log.Printf("checking for configs in /: %v", err)
		return
	}
	existsInCache := false
	cacheDir := os.Getenv("CACHE_DIRECTORY")
	if cacheDir != "" {
		existsInCache, err = checkExists("/var/cache/tailscale")
		if err != nil {
			log.Printf("checking for configs in %s: %v", cacheDir, err)
		}
	}
	existsInDest, err := checkExists(dir)
	if err != nil {
		log.Printf("checking for configs in %s: %v", dir, err)
		return
	}

	switch {
	case !existsInRoot && !existsInCache:
		// No leftover files, nothing to do.
		return
	case existsInDest:
		// Already have "canonical" configs, just delete any remnants
		// (below).
	case existsInCache:
		// CACHE_DIRECTORY takes precedence over /, move files from
		// there.
		if err := moveFiles(cacheDir); err != nil {
			log.Print(err)
			return
		}
	case existsInRoot:
		// Files from root is better than nothing.
		if err := moveFiles("/"); err != nil {
			log.Print(err)
			return
		}
	}

	// If moving succeeded, or we didn't need to move files, try to
	// delete any leftover files, but it's okay if we can't delete
	// them for some reason.
	dirs := []string{}
	if existsInCache {
		dirs = append(dirs, cacheDir)
	}
	if existsInRoot {
		dirs = append(dirs, "/")
	}
	for _, d := range dirs {
		for _, file := range files {
			p := filepath.Join(d, file)
			_, err := os.Stat(p)
			if os.IsNotExist(err) {
				continue
			} else if err != nil {
				log.Printf("stat %q: %v", p, err)
				return
			}
			if err := os.Remove(p); err != nil {
				log.Printf("rm %q: %v", p, err)
			}
		}
	}
}

// New returns a new log policy (a logger and its instance ID) for a
// given collection name.
func New(collection string) *Policy {
	var lflags int
	if term.IsTerminal(2) || runtime.GOOS == "windows" {
		lflags = 0
	} else {
		lflags = log.LstdFlags
	}
	if v, _ := strconv.ParseBool(os.Getenv("TS_DEBUG_LOG_TIME")); v {
		lflags = log.LstdFlags | log.Lmicroseconds
	}
	if runningUnderSystemd() {
		// If journalctl is going to prepend its own timestamp
		// anyway, no need to add one.
		lflags = 0
	}
	console := log.New(stderrWriter{}, "", lflags)

	var earlyErrBuf bytes.Buffer
	earlyLogf := func(format string, a ...interface{}) {
		fmt.Fprintf(&earlyErrBuf, format, a...)
		earlyErrBuf.WriteByte('\n')
	}

	dir := logsDir(earlyLogf)

	cmdName := version.CmdName()
	tryFixLogStateLocation(dir, cmdName)

	cfgPath := filepath.Join(dir, fmt.Sprintf("%s.log.conf", cmdName))
	var oldc *Config
	data, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		earlyLogf("logpolicy.Read %v: %v", cfgPath, err)
		oldc = &Config{}
		oldc.Collection = collection
	} else {
		oldc, err = ConfigFromBytes(data)
		if err != nil {
			earlyLogf("logpolicy.Config unmarshal: %v", err)
			oldc = &Config{}
		}
	}

	newc := *oldc
	if newc.Collection != collection {
		log.Printf("logpolicy.Config: config collection %q does not match %q", newc.Collection, collection)
		// We picked up an incompatible config file.
		// Regenerate the private ID.
		newc.PrivateID = logtail.PrivateID{}
		newc.Collection = collection
	}
	if newc.PrivateID.IsZero() {
		newc.PrivateID, err = logtail.NewPrivateID()
		if err != nil {
			log.Fatalf("logpolicy: NewPrivateID() should never fail")
		}
	}
	newc.PublicID = newc.PrivateID.Public()
	if newc != *oldc {
		if err := newc.save(cfgPath); err != nil {
			earlyLogf("logpolicy.Config.Save: %v", err)
		}
	}

	c := logtail.Config{
		Collection: newc.Collection,
		PrivateID:  newc.PrivateID,
		Stderr:     logWriter{console},
		NewZstdEncoder: func() logtail.Encoder {
			w, err := smallzstd.NewEncoder(nil)
			if err != nil {
				panic(err)
			}
			return w
		},
		HTTPC: &http.Client{Transport: newLogtailTransport(logtail.DefaultHost)},
	}

	filchBuf, filchErr := filch.New(filepath.Join(dir, cmdName), filch.Options{})
	if filchBuf != nil {
		c.Buffer = filchBuf
	}
	lw := logtail.NewLogger(c, log.Printf)
	log.SetFlags(0) // other logflags are set on console, not here
	log.SetOutput(lw)

	log.Printf("Program starting: v%v, Go %v: %#v",
		version.Long,
		goVersion(),
		os.Args)
	log.Printf("LogID: %v", newc.PublicID)
	if filchErr != nil {
		log.Printf("filch failed: %v", filchErr)
	}
	if earlyErrBuf.Len() != 0 {
		log.Printf("%s", earlyErrBuf.Bytes())
	}

	return &Policy{
		Logtail:  lw,
		PublicID: newc.PublicID,
	}
}

// SetVerbosityLevel controls the verbosity level that should be
// written to stderr. 0 is the default (not verbose). Levels 1 or higher
// are increasingly verbose.
//
// It should not be changed concurrently with log writes.
func (p *Policy) SetVerbosityLevel(level int) {
	p.Logtail.SetVerbosityLevel(level)
}

// Close immediately shuts down the logger.
func (p *Policy) Close() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.Shutdown(ctx)
}

// Shutdown gracefully shuts down the logger, finishing any current
// log upload if it can be done before ctx is canceled.
func (p *Policy) Shutdown(ctx context.Context) error {
	if p.Logtail != nil {
		log.Printf("flushing log.")
		return p.Logtail.Shutdown(ctx)
	}
	return nil
}

// newLogtailTransport returns the HTTP Transport we use for uploading
// logs to the given host name.
func newLogtailTransport(host string) *http.Transport {
	// Start with a copy of http.DefaultTransport and tweak it a bit.
	tr := http.DefaultTransport.(*http.Transport).Clone()

	tr.Proxy = tshttpproxy.ProxyFromEnvironment
	tshttpproxy.SetTransportGetProxyConnectHeader(tr)

	// We do our own zstd compression on uploads, and responses never contain any payload,
	// so don't send "Accept-Encoding: gzip" to save a few bytes on the wire, since there
	// will never be any body to decompress:
	tr.DisableCompression = true

	// Log whenever we dial:
	tr.DialContext = func(ctx context.Context, netw, addr string) (net.Conn, error) {
		nd := netns.FromDialer(&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		})
		t0 := time.Now()
		c, err := nd.DialContext(ctx, netw, addr)
		d := time.Since(t0).Round(time.Millisecond)
		if err != nil {
			log.Printf("logtail: dial %q failed: %v (in %v)", addr, err, d)
		} else {
			log.Printf("logtail: dialed %q in %v", addr, d)
		}
		return c, err
	}

	// We're contacting exactly 1 hostname, so the default's 100
	// max idle conns is very high for our needs. Even 2 is
	// probably double what we need:
	tr.MaxIdleConns = 2

	// Provide knob to force HTTP/1 for log uploads.
	// TODO(bradfitz): remove this debug knob once we've decided
	// to upload via HTTP/1 or HTTP/2 (probably HTTP/1). Or we might just enforce
	// it server-side.
	if h1, _ := strconv.ParseBool(os.Getenv("TS_DEBUG_FORCE_H1_LOGS")); h1 {
		tr.TLSClientConfig = nil // DefaultTransport's was already initialized w/ h2
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{}
	}

	tr.TLSClientConfig = tlsdial.Config(host, tr.TLSClientConfig)

	return tr
}

func goVersion() string {
	v := strings.TrimPrefix(runtime.Version(), "go")
	if racebuild.On {
		return v + "-race"
	}
	return v
}
