// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package logpolicy manages the creation or reuse of logtail loggers,
// caching collection instance state on disk for use on future runs of
// programs on the same machine.
package logpolicy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
	"tailscale.com/atomicfile"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/log/filelogger"
	"tailscale.com/logtail"
	"tailscale.com/logtail/filch"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netknob"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/netx"
	"tailscale.com/net/tlsdial"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/must"
	"tailscale.com/util/racebuild"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/testenv"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

var getLogTargetOnce struct {
	sync.Once
	v string // URL of logs server, or empty for default
}

func getLogTarget() string {
	getLogTargetOnce.Do(func() {
		envTarget, _ := os.LookupEnv("TS_LOG_TARGET")
		getLogTargetOnce.v, _ = policyclient.Get().GetString(pkey.LogTarget, envTarget)
	})

	return getLogTargetOnce.v
}

// LogURL is the base URL for the configured logtail server, or the default.
// It is guaranteed to not terminate with any forward slashes.
func LogURL() string {
	if v := getLogTarget(); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "https://" + logtail.DefaultHost
}

// LogHost returns the hostname only (without port) of the configured
// logtail server, or the default.
//
// Deprecated: Use LogURL instead.
func LogHost() string {
	if v := getLogTarget(); v != "" {
		if u, err := url.Parse(v); err == nil {
			return u.Hostname()
		}
	}
	return logtail.DefaultHost
}

// Config represents an instance of logs in a collection.
type Config struct {
	Collection string
	PrivateID  logid.PrivateID
	PublicID   logid.PublicID
}

// Policy is a logger and its public ID.
type Policy struct {
	// Logtail is the logger.
	Logtail *logtail.Logger
	// PublicID is the logger's instance identifier.
	// It may be the zero value if logging is not in use.
	PublicID logid.PublicID
	// Logf is where to write informational messages about this Logger.
	Logf logger.Logf
}

// NewConfig creates a Config with collection and a newly generated PrivateID.
func NewConfig(collection string) *Config {
	id := must.Get(logid.NewPrivateID())
	return &Config{
		Collection: collection,
		PrivateID:  id,
		PublicID:   id.Public(),
	}
}

// Validate verifies that the Config matches the collection,
// and that the PrivateID and PublicID pair are sensible.
func (c *Config) Validate(collection string) error {
	switch {
	case c == nil:
		return errors.New("config is nil")
	case c.Collection != collection:
		return fmt.Errorf("config collection %q does not match %q", c.Collection, collection)
	case c.PrivateID.IsZero():
		return errors.New("config has zero PrivateID")
	case c.PrivateID.Public() != c.PublicID:
		return errors.New("config PrivateID does not match PublicID")
	}
	return nil
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
func (c *Config) Save(stateFile string) error {
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

// ConfigFromFile reads a Config from a JSON file.
func ConfigFromFile(statefile string) (*Config, error) {
	b, err := os.ReadFile(statefile)
	if err != nil {
		return nil, err
	}
	return ConfigFromBytes(b)
}

// ConfigFromBytes parses a Config from its JSON encoding.
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

// LogsDir returns the directory to use for log configuration and
// buffer storage.
func LogsDir(logf logger.Logf) string {
	if d := os.Getenv("TS_LOGS_DIR"); d != "" {
		fi, err := os.Stat(d)
		if err == nil && fi.IsDir() {
			return d
		}
	}

	switch runtime.GOOS {
	case "windows":
		if version.CmdName() == "tailscaled" {
			// In the common case, when tailscaled is run as the Local System (as a service),
			// we want to use %ProgramData% (C:\ProgramData\Tailscale), aside the
			// system state config with the machine key, etc. But if that directory's
			// not accessible, then it's probably because the user is running tailscaled
			// as a regular user (perhaps in userspace-networking/SOCK5 mode) and we should
			// just use the %LocalAppData% instead. In a user context, %LocalAppData% isn't
			// subject to random deletions from Windows system updates.
			dir := filepath.Join(os.Getenv("ProgramData"), "Tailscale")
			if winProgramDataAccessible(dir) {
				logf("logpolicy: using dir %v", dir)
				return dir
			}
		}
		dir := filepath.Join(os.Getenv("LocalAppData"), "Tailscale")
		logf("logpolicy: using LocalAppData dir %v", dir)
		return dir
	case "linux":
		if distro.Get() == distro.JetKVM {
			return "/userdata/tailscale/var"
		}
		// STATE_DIRECTORY is set by systemd 240+ but we support older
		// systems-d. For example, Ubuntu 18.04 (Bionic Beaver) is 237.
		systemdStateDir := os.Getenv("STATE_DIRECTORY")
		if systemdStateDir != "" {
			logf("logpolicy: using $STATE_DIRECTORY, %q", systemdStateDir)
			return systemdStateDir
		}
	case "js":
		logf("logpolicy: no logs directory in the browser")
		return ""
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
	tmp, err := os.MkdirTemp("", "tailscaled-log-*")
	if err != nil {
		panic("no safe place found to store log state")
	}
	logf("logpolicy: using temp directory, %q", tmp)
	return tmp
}

// runningUnderSystemd reports whether we're running under systemd.
func runningUnderSystemd() bool {
	if runtime.GOOS == "linux" && os.Getppid() == 1 {
		slurp, _ := os.ReadFile("/proc/1/stat")
		return bytes.HasPrefix(slurp, []byte("1 (systemd) "))
	}
	return false
}

func redirectStderrToLogPanics() bool {
	return runningUnderSystemd() || envknob.Bool("TS_PLEASE_PANIC")
}

// winProgramDataAccessible reports whether the directory (assumed to
// be a Windows %ProgramData% directory) is accessible to the current
// process. It's created if needed.
func winProgramDataAccessible(dir string) bool {
	if err := os.MkdirAll(dir, 0700); err != nil {
		// TODO: windows ACLs
		return false
	}
	// The C:\ProgramData\Tailscale directory should be locked down
	// by with ACLs to only be readable by the local system so a
	// regular user shouldn't be able to do this operation:
	if _, err := os.ReadDir(dir); err != nil {
		return false
	}
	return true
}

// tryFixLogStateLocation is a temporary fixup for
// https://github.com/tailscale/tailscale/issues/247 . We accidentally
// wrote logging state files to /, and then later to $CACHE_DIRECTORY
// (which is incorrect because the log ID is not reconstructible if
// deleted - it's state, not cache data).
//
// If log state for cmdname exists in / or $CACHE_DIRECTORY, and no
// log state for that command exists in dir, then the log state is
// moved from wherever it does exist, into dir. Leftover logs state
// in / and $CACHE_DIRECTORY is deleted.
func tryFixLogStateLocation(dir, cmdname string, logf logger.Logf) {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		// These are the OSes where we might have written stuff into
		// root. Others use different logic to find the logs storage
		// dir.
	default:
		return
	}
	if cmdname == "" {
		logf("[unexpected] no cmdname given to tryFixLogStateLocation, please file a bug at https://github.com/tailscale/tailscale")
		return
	}
	if dir == "/" {
		// Trying to store things in / still. That's a bug, but don't
		// abort hard.
		logf("[unexpected] storing logging config in /, please file a bug at https://github.com/tailscale/tailscale")
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
		logf("checking for configs in /: %v", err)
		return
	}
	existsInCache := false
	cacheDir := os.Getenv("CACHE_DIRECTORY")
	if cacheDir != "" {
		existsInCache, err = checkExists("/var/cache/tailscale")
		if err != nil {
			logf("checking for configs in %s: %v", cacheDir, err)
		}
	}
	existsInDest, err := checkExists(dir)
	if err != nil {
		logf("checking for configs in %s: %v", dir, err)
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
			logf("%v", err)
			return
		}
	case existsInRoot:
		// Files from root is better than nothing.
		if err := moveFiles("/"); err != nil {
			logf("%v", err)
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
				logf("stat %q: %v", p, err)
				return
			}
			if err := os.Remove(p); err != nil {
				logf("rm %q: %v", p, err)
			}
		}
	}
}

// Deprecated: Use [Options.New] instead.
func New(collection string, netMon *netmon.Monitor, health *health.Tracker, logf logger.Logf) *Policy {
	return Options{
		Collection: collection,
		NetMon:     netMon,
		Health:     health,
		Logf:       logf,
	}.New()
}

// Options is used to construct a [Policy].
type Options struct {
	// Collection is a required collection to upload logs under.
	// Collection is a namespace for the type logs.
	// For example, logs for a node use "tailnode.log.tailscale.io".
	Collection string

	// Dir is an optional directory to store the log configuration.
	// If empty, [LogsDir] is used.
	Dir string

	// CmdName is an optional name of the current binary.
	// If empty, [version.CmdName] is used.
	CmdName string

	// NetMon is an optional parameter for monitoring.
	// If non-nil, it's used to do faster interface lookups.
	NetMon *netmon.Monitor

	// Health is an optional parameter for health status.
	// If non-nil, it's used to construct the default HTTP client.
	Health *health.Tracker

	// Logf is an optional logger to use.
	// If nil, [log.Printf] will be used instead.
	Logf logger.Logf

	// HTTPC is an optional client to use upload logs.
	// If nil, [TransportOptions.New] is used to construct a new client
	// with that particular transport sending logs to the default logs server.
	HTTPC *http.Client

	// MaxBufferSize is the maximum size of the log buffer.
	// This controls the amount of logs that can be temporarily stored
	// before the logs can be successfully upload.
	// If zero, a default buffer size is chosen.
	MaxBufferSize int

	// MaxUploadSize is the maximum size per upload.
	// This should only be set by clients that have been authenticated
	// with the logging service as having a higher upload limit.
	// If zero, a default upload size is chosen.
	MaxUploadSize int
}

// init initializes the log policy and returns a logtail.Config and the
// Policy.
func (opts Options) init(disableLogging bool) (*logtail.Config, *Policy) {
	if hostinfo.IsNATLabGuestVM() {
		// In NATLab Gokrazy instances, tailscaled comes up concurently with
		// DHCP and the doesn't have DNS for a while. Wait for DHCP first.
		awaitGokrazyNetwork()
	}
	var lflags int
	if term.IsTerminal(2) || runtime.GOOS == "windows" {
		lflags = 0
	} else {
		lflags = log.LstdFlags
	}
	if envknob.Bool("TS_DEBUG_LOG_TIME") {
		lflags = log.LstdFlags | log.Lmicroseconds
	}
	if runningUnderSystemd() {
		// If journalctl is going to prepend its own timestamp
		// anyway, no need to add one.
		lflags = 0
	}
	console := log.New(stderrWriter{}, "", lflags)

	var earlyErrBuf bytes.Buffer
	earlyLogf := func(format string, a ...any) {
		fmt.Fprintf(&earlyErrBuf, format, a...)
		earlyErrBuf.WriteByte('\n')
	}

	if opts.Dir == "" {
		opts.Dir = LogsDir(earlyLogf)
	}
	if opts.CmdName == "" {
		opts.CmdName = version.CmdName()
	}

	useStdLogger := opts.Logf == nil
	if useStdLogger {
		opts.Logf = log.Printf
	}
	tryFixLogStateLocation(opts.Dir, opts.CmdName, opts.Logf)

	cfgPath := filepath.Join(opts.Dir, fmt.Sprintf("%s.log.conf", opts.CmdName))

	if runtime.GOOS == "windows" {
		switch opts.CmdName {
		case "tailscaled":
			// Tailscale 1.14 and before stored state under %LocalAppData%
			// (usually "C:\WINDOWS\system32\config\systemprofile\AppData\Local"
			// when tailscaled.exe is running as a non-user system service).
			// However it is frequently cleared for almost any reason: Windows
			// updates, System Restore, even various System Cleaner utilities.
			//
			// The Windows service previously ran as tailscale-ipn.exe, so
			// machines which ran very old versions might still have their
			// log conf named %LocalAppData%\tailscale-ipn.log.conf
			//
			// Machines which started using Tailscale more recently will have
			// %LocalAppData%\tailscaled.log.conf
			//
			// Attempt to migrate the log conf to C:\ProgramData\Tailscale
			oldDir := filepath.Join(os.Getenv("LocalAppData"), "Tailscale")

			oldPath := filepath.Join(oldDir, "tailscaled.log.conf")
			if fi, err := os.Stat(oldPath); err != nil || !fi.Mode().IsRegular() {
				// *Only* if tailscaled.log.conf does not exist,
				// check for tailscale-ipn.log.conf
				oldPathOldCmd := filepath.Join(oldDir, "tailscale-ipn.log.conf")
				if fi, err := os.Stat(oldPathOldCmd); err == nil && fi.Mode().IsRegular() {
					oldPath = oldPathOldCmd
				}
			}

			cfgPath = paths.TryConfigFileMigration(earlyLogf, oldPath, cfgPath)
		case "tailscale-ipn":
			for _, oldBase := range []string{"wg64.log.conf", "wg32.log.conf"} {
				oldConf := filepath.Join(opts.Dir, oldBase)
				if fi, err := os.Stat(oldConf); err == nil && fi.Mode().IsRegular() {
					cfgPath = paths.TryConfigFileMigration(earlyLogf, oldConf, cfgPath)
					break
				}
			}
		}
	}

	newc, err := ConfigFromFile(cfgPath)
	if err != nil {
		earlyLogf("logpolicy.ConfigFromFile %v: %v", cfgPath, err)
	}
	if err := newc.Validate(opts.Collection); err != nil {
		earlyLogf("logpolicy.Config.Validate for %v: %v", cfgPath, err)
		newc = NewConfig(opts.Collection)
		if err := newc.Save(cfgPath); err != nil {
			earlyLogf("logpolicy.Config.Save for %v: %v", cfgPath, err)
		}
	}

	conf := logtail.Config{
		Collection:    newc.Collection,
		PrivateID:     newc.PrivateID,
		Stderr:        logWriter{console},
		CompressLogs:  true,
		MaxUploadSize: opts.MaxUploadSize,
	}
	if opts.Collection == logtail.CollectionNode {
		conf.MetricsDelta = clientmetric.EncodeLogTailMetricsDelta
		conf.IncludeProcID = true
		conf.IncludeProcSequence = true
	}

	if disableLogging {
		opts.Logf("You have disabled logging. Tailscale will not be able to provide support.")
		conf.HTTPC = &http.Client{Transport: noopPretendSuccessTransport{}}
	} else {
		// Only attach an on-disk filch buffer if we are going to be sending logs.
		// No reason to persist them locally just to drop them later.
		attachFilchBuffer(&conf, opts.Dir, opts.CmdName, opts.MaxBufferSize, opts.Logf)
		conf.HTTPC = opts.HTTPC

		logHost := logtail.DefaultHost
		if val := getLogTarget(); val != "" {
			opts.Logf("You have enabled a non-default log target. Doing without being told to by Tailscale staff or your network administrator will make getting support difficult.")
			conf.BaseURL = val
			u, _ := url.Parse(val)
			logHost = u.Host
		}

		if conf.HTTPC == nil {
			conf.HTTPC = &http.Client{Transport: TransportOptions{
				Host:   logHost,
				NetMon: opts.NetMon,
				Health: opts.Health,
				Logf:   opts.Logf,
			}.New()}
		}
	}
	lw := logtail.NewLogger(conf, opts.Logf)

	var logOutput io.Writer = lw

	if runtime.GOOS == "windows" && conf.Collection == logtail.CollectionNode {
		logID := newc.PublicID.String()
		exe, _ := os.Executable()
		if strings.EqualFold(filepath.Base(exe), "tailscaled.exe") {
			diskLogf := filelogger.New("tailscale-service", logID, lw.Logf)
			logOutput = logger.FuncWriter(diskLogf)
		}
	}

	if useStdLogger {
		log.SetFlags(0) // other log flags are set on console, not here
		log.SetOutput(logOutput)
	}

	opts.Logf("Program starting: v%v, Go %v: %#v",
		version.Long(),
		goVersion(),
		os.Args)
	opts.Logf("LogID: %v", newc.PublicID)
	if earlyErrBuf.Len() != 0 {
		opts.Logf("%s", earlyErrBuf.Bytes())
	}

	return &conf, &Policy{
		Logtail:  lw,
		PublicID: newc.PublicID,
		Logf:     opts.Logf,
	}
}

// New returns a new log policy (a logger and its instance ID).
func (opts Options) New() *Policy {
	disableLogging := envknob.NoLogsNoSupport() || testenv.InTest() || runtime.GOOS == "plan9" || !buildfeatures.HasLogTail
	_, policy := opts.init(disableLogging)
	return policy
}

// attachFilchBuffer creates an on-disk ring buffer using filch and attaches
// it to the logtail config. Note that this is optional; if no buffer is set,
// logtail will use an in-memory buffer.
func attachFilchBuffer(conf *logtail.Config, dir, cmdName string, maxFileSize int, logf logger.Logf) {
	filchOptions := filch.Options{
		ReplaceStderr: redirectStderrToLogPanics(),
		MaxFileSize:   maxFileSize,
	}
	filchPrefix := filepath.Join(dir, cmdName)

	// NAS disks cannot hibernate if we're writing logs to them all the time.
	// https://github.com/tailscale/tailscale/issues/3551
	if runtime.GOOS == "linux" && (distro.Get() == distro.Synology || distro.Get() == distro.QNAP) {
		tmpfsLogs := "/tmp/tailscale-logs"
		if err := os.MkdirAll(tmpfsLogs, 0755); err == nil {
			filchPrefix = filepath.Join(tmpfsLogs, cmdName)
			filchOptions.MaxFileSize = 1 << 20
		} else {
			// not a fatal error, we can leave the log files on the spinning disk
			logf("Unable to create /tmp directory for log storage: %v\n", err)
		}
	}

	filchBuf, filchErr := filch.New(filchPrefix, filchOptions)
	if filchBuf != nil {
		conf.Buffer = filchBuf
		if filchBuf.OrigStderr != nil {
			conf.Stderr = filchBuf.OrigStderr
		}
	}
	if filchErr != nil {
		logf("filch failed: %v", filchErr)
	}
}

// dialLog is used by NewLogtailTransport to log the happy path of its
// own dialing.
//
// By default it goes nowhere and is only enabled when
// tailscaled's in verbose mode.
//
// log.Printf isn't used so its own logs don't loop back into logtail
// in the happy path, thus generating more logs.
var dialLog = log.New(io.Discard, "logtail: ", log.LstdFlags|log.Lmsgprefix)

// SetVerbosityLevel controls the verbosity level that should be
// written to stderr. 0 is the default (not verbose). Levels 1 or higher
// are increasingly verbose.
//
// It should not be changed concurrently with log writes.
func (p *Policy) SetVerbosityLevel(level int) {
	p.Logtail.SetVerbosityLevel(level)
	if level > 0 {
		dialLog.SetOutput(os.Stderr)
	}
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
		p.Logf("flushing log.")
		return p.Logtail.Shutdown(ctx)
	}
	return nil
}

// MakeDialFunc creates a net.Dialer.DialContext function specialized for use
// by logtail.
// It does the following:
//   - If DNS lookup fails, consults the bootstrap DNS list of Tailscale hostnames.
//   - If TLS connection fails, try again using LetsEncrypt's built-in root certificate,
//     for the benefit of older OS platforms which might not include it.
//
// The netMon parameter is optional. It should be specified in environments where
// Tailscaled is manipulating the routing table.
func MakeDialFunc(netMon *netmon.Monitor, logf logger.Logf) netx.DialFunc {
	if netMon == nil {
		netMon = netmon.NewStatic()
	}
	return func(ctx context.Context, netw, addr string) (net.Conn, error) {
		return dialContext(ctx, netw, addr, netMon, logf)
	}
}

func dialContext(ctx context.Context, netw, addr string, netMon *netmon.Monitor, logf logger.Logf) (net.Conn, error) {
	nd := netns.FromDialer(logf, netMon, &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: netknob.PlatformTCPKeepAlive(),
	})
	t0 := time.Now()
	c, err := nd.DialContext(ctx, netw, addr)
	d := time.Since(t0).Round(time.Millisecond)
	if err == nil {
		dialLog.Printf("dialed %q in %v", addr, d)
		return c, nil
	}

	if version.IsWindowsGUI() && strings.HasPrefix(netw, "tcp") {
		if c, err := safesocket.ConnectContext(ctx, ""); err == nil {
			fmt.Fprintf(c, "CONNECT %s HTTP/1.0\r\n\r\n", addr)
			br := bufio.NewReader(c)
			res, err := http.ReadResponse(br, nil)
			if err == nil && res.StatusCode != 200 {
				err = errors.New(res.Status)
			}
			if err != nil {
				logf("logtail: CONNECT response error from tailscaled: %v", err)
				c.Close()
			} else {
				dialLog.Printf("connected via tailscaled")
				return c, nil
			}
		}
	}

	// If we failed to dial, try again with bootstrap DNS.
	logf("logtail: dial %q failed: %v (in %v), trying bootstrap...", addr, err, d)
	dnsCache := &dnscache.Resolver{
		Forward:          dnscache.Get().Forward, // use default cache's forwarder
		UseLastGood:      true,
		LookupIPFallback: dnsfallback.MakeLookupFunc(logf, netMon),
	}
	dialer := dnscache.Dialer(nd.DialContext, dnsCache)
	c, err = dialer(ctx, netw, addr)
	if err == nil {
		logf("logtail: bootstrap dial succeeded")
	}
	return c, err
}

// Deprecated: Use [TransportOptions.New] instead.
func NewLogtailTransport(host string, netMon *netmon.Monitor, health *health.Tracker, logf logger.Logf) http.RoundTripper {
	return TransportOptions{Host: host, NetMon: netMon, Health: health, Logf: logf}.New()
}

// TransportOptions is used to construct an [http.RoundTripper].
type TransportOptions struct {
	// Host is the optional hostname of the logs server.
	// If empty, then [logtail.DefaultHost] is used.
	Host string

	// NetMon is an optional parameter for monitoring.
	// If non-nil, it's used to do faster interface lookups.
	NetMon *netmon.Monitor

	// Health is an optional parameter for health status.
	// If non-nil, it's used to construct the default HTTP client.
	Health *health.Tracker

	// Logf is an optional logger to use.
	// If nil, [log.Printf] will be used instead.
	Logf logger.Logf

	// TLSClientConfig is an optional TLS configuration to use.
	// If non-nil, the configuration will be cloned.
	TLSClientConfig *tls.Config
}

// New returns an HTTP Transport particularly suited to uploading logs
// to the given host name. See [DialContext] for details on how it works.
func (opts TransportOptions) New() http.RoundTripper {
	if testenv.InTest() || envknob.NoLogsNoSupport() {
		return noopPretendSuccessTransport{}
	}
	if opts.NetMon == nil {
		opts.NetMon = netmon.NewStatic()
	}
	// Start with a copy of http.DefaultTransport and tweak it a bit.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if opts.TLSClientConfig != nil {
		tr.TLSClientConfig = opts.TLSClientConfig.Clone()
	}

	if buildfeatures.HasUseProxy {
		tr.Proxy = feature.HookProxyFromEnvironment.GetOrNil()
		if set, ok := feature.HookProxySetTransportGetProxyConnectHeader.GetOk(); ok {
			set(tr)
		}
	}

	// We do our own zstd compression on uploads, and responses never contain any payload,
	// so don't send "Accept-Encoding: gzip" to save a few bytes on the wire, since there
	// will never be any body to decompress:
	tr.DisableCompression = true

	// Log whenever we dial:
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	tr.DialContext = MakeDialFunc(opts.NetMon, opts.Logf)

	// We're uploading logs ideally infrequently, with specific timing that will
	// change over time. Try to keep the connection open, to avoid repeatedly
	// paying the cost of TLS setup.
	tr.IdleConnTimeout = time.Hour

	// We're contacting exactly 1 hostname, so the default's 100
	// max idle conns is very high for our needs. Even 2 is
	// probably double what we need:
	tr.MaxIdleConns = 2

	// Provide knob to force HTTP/1 for log uploads.
	// TODO(bradfitz): remove this debug knob once we've decided
	// to upload via HTTP/1 or HTTP/2 (probably HTTP/1). Or we might just enforce
	// it server-side.
	if envknob.Bool("TS_DEBUG_FORCE_H1_LOGS") {
		tr.TLSClientConfig = nil // DefaultTransport's was already initialized w/ h2
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{}
	}

	tr.TLSClientConfig = tlsdial.Config(opts.Health, tr.TLSClientConfig)
	// Force TLS 1.3 since we know log.tailscale.com supports it.
	tr.TLSClientConfig.MinVersion = tls.VersionTLS13

	return tr
}

func goVersion() string {
	v := strings.TrimPrefix(runtime.Version(), "go")
	if racebuild.On {
		return v + "-race"
	}
	return v
}

type noopPretendSuccessTransport struct{}

func (noopPretendSuccessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	io.Copy(io.Discard, req.Body)
	req.Body.Close()
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
	}, nil
}

func awaitGokrazyNetwork() {
	if runtime.GOOS != "linux" || distro.Get() != distro.Gokrazy {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for {
		// Before DHCP finishes, the /etc/resolv.conf file has just "#MANUAL".
		all, _ := os.ReadFile("/etc/resolv.conf")
		if bytes.Contains(all, []byte("nameserver ")) {
			good := true
			firstLine, _, ok := strings.Cut(string(all), "\n")
			if ok {
				ns, ok := strings.CutPrefix(firstLine, "nameserver ")
				if ok {
					if ip, err := netip.ParseAddr(ns); err == nil && ip.Is6() && !ip.IsLinkLocalUnicast() {
						good = haveGlobalUnicastIPv6()
					}
				}
			}
			if good {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// haveGlobalUnicastIPv6 reports whether the machine has a IPv6 non-private
// (non-ULA) global unicast address.
//
// It's only intended for use in natlab integration tests so only works on
// Linux/macOS now and not environments (such as Android) where net.Interfaces
// doesn't work directly.
func haveGlobalUnicastIPv6() bool {
	ifs, _ := net.Interfaces()
	for _, ni := range ifs {
		aa, _ := ni.Addrs()
		for _, a := range aa {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, _ := netip.AddrFromSlice(ipn.IP)
			if ip.Is6() && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return true
			}
		}
	}
	return false
}
