// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android && !ios

package dns

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"tailscale.com/feature"
	"tailscale.com/health"
	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/version/distro"
)

// writeResolvConf writes DNS configuration in resolv.conf format to the given writer.
func writeResolvConf(w io.Writer, servers []netip.Addr, domains []dnsname.FQDN) error {
	c := &resolvconffile.Config{
		Nameservers:   servers,
		SearchDomains: domains,
	}
	return c.Write(w)
}

func readResolv(r io.Reader) (OSConfig, error) {
	c, err := resolvconffile.Parse(r)
	if err != nil {
		return OSConfig{}, err
	}
	return OSConfig{
		Nameservers:   c.Nameservers,
		SearchDomains: c.SearchDomains,
	}, nil
}

// resolvOwner returns the apparent owner of the resolv.conf
// configuration in bs - one of "resolvconf", "systemd-resolved" or
// "NetworkManager", or "" if no known owner was found.
//
//lint:ignore U1000 used in linux and freebsd code
func resolvOwner(bs []byte) string {
	likely := ""
	b := bytes.NewBuffer(bs)
	for {
		line, err := b.ReadString('\n')
		if err != nil {
			return likely
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line[0] != '#' {
			// First non-empty, non-comment line. Assume the owner
			// isn't hiding further down.
			return likely
		}

		if strings.Contains(line, "systemd-resolved") {
			likely = "systemd-resolved"
		} else if strings.Contains(line, "NetworkManager") {
			likely = "NetworkManager"
		} else if strings.Contains(line, "resolvconf") {
			likely = "resolvconf"
		}
	}
}

// isResolvedRunning reports whether systemd-resolved is running on the system,
// even if it is not managing the system DNS settings.
func isResolvedRunning() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	// systemd-resolved is never installed without systemd.
	_, err := exec.LookPath("systemctl")
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, "systemctl", "is-active", "systemd-resolved.service").Run()

	// is-active exits with code 3 if the service is not active.
	return err == nil
}

func restartResolved() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "restart", "systemd-resolved.service").Run()
}

// directManager is an OSConfigurator which replaces /etc/resolv.conf with a file
// generated from the given configuration, creating a backup of its old state.
//
// This way of configuring DNS is precarious, since it does not react
// to the disappearance of the Tailscale interface.
// The caller must call Down before program shutdown
// or as cleanup if the program terminates unexpectedly.
type directManager struct {
	logf   logger.Logf
	health *health.Tracker
	fs     wholeFileFS
	// renameBroken is set if fs.Rename to or from /etc/resolv.conf
	// fails. This can happen in some container runtimes, where
	// /etc/resolv.conf is bind-mounted from outside the container,
	// and therefore /etc and /etc/resolv.conf are different
	// filesystems as far as rename(2) is concerned.
	//
	// In those situations, we fall back to emulating rename with file
	// copies and truncations, which is not as good (opens up a race
	// where a reader can see an empty or partial /etc/resolv.conf),
	// but is better than having non-functioning DNS.
	renameBroken bool

	ctx      context.Context    // valid until Close
	ctxClose context.CancelFunc // closes ctx

	mu             sync.Mutex
	wantResolvConf []byte // if non-nil, what we expect /etc/resolv.conf to contain
	//lint:ignore U1000 used in direct_linux.go
	lastWarnContents []byte // last resolv.conf contents that we warned about
}

//lint:ignore U1000 used in manager_{freebsd,openbsd}.go
func newDirectManager(logf logger.Logf, health *health.Tracker) *directManager {
	return newDirectManagerOnFS(logf, health, directFS{})
}

func newDirectManagerOnFS(logf logger.Logf, health *health.Tracker, fs wholeFileFS) *directManager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &directManager{
		logf:     logf,
		health:   health,
		fs:       fs,
		ctx:      ctx,
		ctxClose: cancel,
	}
	go m.runFileWatcher()
	return m
}

func (m *directManager) readResolvFile(path string) (OSConfig, error) {
	b, err := m.fs.ReadFile(path)
	if err != nil {
		return OSConfig{}, err
	}
	return readResolv(bytes.NewReader(b))
}

// ownedByTailscale reports whether /etc/resolv.conf seems to be a
// tailscale-managed file.
func (m *directManager) ownedByTailscale() (bool, error) {
	isRegular, err := m.fs.Stat(resolvConf)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !isRegular {
		return false, nil
	}
	bs, err := m.fs.ReadFile(resolvConf)
	if err != nil {
		return false, err
	}
	if bytes.Contains(bs, []byte("generated by tailscale")) {
		return true, nil
	}
	return false, nil
}

// backupConfig creates or updates a backup of /etc/resolv.conf, if
// resolv.conf does not currently contain a Tailscale-managed config.
func (m *directManager) backupConfig() error {
	if _, err := m.fs.Stat(resolvConf); err != nil {
		if os.IsNotExist(err) {
			// No resolv.conf, nothing to back up. Also get rid of any
			// existing backup file, to avoid restoring something old.
			m.fs.Remove(backupConf)
			return nil
		}
		return err
	}

	owned, err := m.ownedByTailscale()
	if err != nil {
		return err
	}
	if owned {
		return nil
	}

	return m.rename(resolvConf, backupConf)
}

func (m *directManager) restoreBackup() (restored bool, err error) {
	if _, err := m.fs.Stat(backupConf); err != nil {
		if os.IsNotExist(err) {
			// No backup, nothing we can do.
			return false, nil
		}
		return false, err
	}
	owned, err := m.ownedByTailscale()
	if err != nil {
		return false, err
	}
	_, err = m.fs.Stat(resolvConf)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	resolvConfExists := !os.IsNotExist(err)

	if resolvConfExists && !owned {
		// There's already a non-tailscale config in place, get rid of
		// our backup.
		m.fs.Remove(backupConf)
		return false, nil
	}

	// We own resolv.conf, and a backup exists.
	if err := m.rename(backupConf, resolvConf); err != nil {
		return false, err
	}

	return true, nil
}

// rename tries to rename old to new using m.fs.Rename, and falls back
// to hand-copying bytes and truncating old if that fails.
//
// This is a workaround to /etc/resolv.conf being a bind-mounted file
// some container environments, which cannot be moved elsewhere in
// /etc (because that would be a cross-filesystem move) or deleted
// (because that would break the bind in surprising ways).
func (m *directManager) rename(old, new string) error {
	if !m.renameBroken {
		err := m.fs.Rename(old, new)
		if err == nil {
			return nil
		}
		if runtime.GOOS == "linux" && distro.Get() == distro.Synology {
			// Fail fast. The fallback case below won't work anyway.
			return err
		}
		m.logf("rename of %q to %q failed (%v), falling back to copy+delete", old, new, err)
		m.renameBroken = true
	}

	bs, err := m.fs.ReadFile(old)
	if err != nil {
		return fmt.Errorf("reading %q to rename: %w", old, err)
	}
	if err := m.fs.WriteFile(new, bs, 0644); err != nil {
		return fmt.Errorf("writing to %q in rename of %q: %w", new, old, err)
	}

	// Explicitly set the permissions on the new file. This ensures that
	// if we have a umask set which prevents creating world-readable files,
	// the file will still have the correct permissions once it's renamed
	// into place. See #12609.
	if err := m.fs.Chmod(new, 0644); err != nil {
		return fmt.Errorf("chmod %q in rename of %q: %w", new, old, err)
	}

	if err := m.fs.Remove(old); err != nil {
		err2 := m.fs.Truncate(old)
		if err2 != nil {
			return fmt.Errorf("remove of %q failed (%w) and so did truncate: %v", old, err, err2)
		}
	}
	return nil
}

// setWant sets the expected contents of /etc/resolv.conf, if any.
//
// A value of nil means no particular value is expected.
//
// m takes ownership of want.
func (m *directManager) setWant(want []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wantResolvConf = want
}

func (m *directManager) SetDNS(config OSConfig) (err error) {
	defer func() {
		if err != nil && errors.Is(err, fs.ErrPermission) && runtime.GOOS == "linux" &&
			distro.Get() == distro.Synology && os.Geteuid() != 0 {
			// On Synology (notably DSM7 where we don't run as root), ignore all
			// DNS configuration errors for now. We don't have permission.
			// See https://github.com/tailscale/tailscale/issues/4017
			m.logf("ignoring SetDNS permission error on Synology (Issue 4017); was: %v", err)
			err = nil
		}
	}()
	m.setWant(nil) // reset our expectations before any work
	var changed bool
	if config.IsZero() {
		changed, err = m.restoreBackup()
		if err != nil {
			return err
		}
	} else {
		changed = true
		if err := m.backupConfig(); err != nil {
			return err
		}

		buf := new(bytes.Buffer)
		writeResolvConf(buf, config.Nameservers, config.SearchDomains)
		if err := m.atomicWriteFile(m.fs, resolvConf, buf.Bytes(), 0644); err != nil {
			return err
		}

		// Now that we've successfully written to the file, lock it in.
		// If we see /etc/resolv.conf with different contents, we know somebody
		// else trampled on it.
		m.setWant(buf.Bytes())
	}

	// We might have taken over a configuration managed by resolved,
	// in which case it will notice this on restart and gracefully
	// start using our configuration. This shouldn't happen because we
	// try to manage DNS through resolved when it's around, but as a
	// best-effort fallback if we messed up the detection, try to
	// restart resolved to make the system configuration consistent.
	//
	// We take care to only kick systemd-resolved if we've made some
	// change to the system's DNS configuration, because this codepath
	// can end up running in cases where the user has manually
	// configured /etc/resolv.conf to point to systemd-resolved (but
	// it's not managed explicitly by systemd-resolved), *and* has
	// --accept-dns=false, meaning we pass an empty configuration to
	// the running DNS manager. In that very edge-case scenario, we
	// cause a disruptive DNS outage each time we reset an empty
	// OS configuration.
	if changed && isResolvedRunning() && !runningAsGUIDesktopUser() {
		t0 := time.Now()
		err := restartResolved()
		d := time.Since(t0).Round(time.Millisecond)
		if err != nil {
			m.logf("error restarting resolved after %v: %v", d, err)
		} else {
			m.logf("restarted resolved after %v", d)
		}
	}

	return nil
}

func (m *directManager) SupportsSplitDNS() bool {
	return false
}

func (m *directManager) GetBaseConfig() (OSConfig, error) {
	owned, err := m.ownedByTailscale()
	if err != nil {
		return OSConfig{}, err
	}
	fileToRead := resolvConf
	if owned {
		fileToRead = backupConf
	}

	oscfg, err := m.readResolvFile(fileToRead)
	if err != nil {
		return OSConfig{}, err
	}

	// On some systems, the backup configuration file is actually a
	// symbolic link to something owned by another DNS service (commonly,
	// resolved). Thus, it can be updated out from underneath us to contain
	// the Tailscale service IP, which results in an infinite loop of us
	// trying to send traffic to resolved, which sends back to us, and so
	// on. To solve this, drop the Tailscale service IP from the base
	// configuration; we do this in all situations since there's
	// essentially no world where we want to forward to ourselves.
	//
	// See: https://github.com/tailscale/tailscale/issues/7816
	var removed bool
	oscfg.Nameservers = slices.DeleteFunc(oscfg.Nameservers, func(ip netip.Addr) bool {
		if ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6() {
			removed = true
			return true
		}
		return false
	})
	if removed {
		m.logf("[v1] dropped Tailscale IP from base config that was a symlink")
	}
	return oscfg, nil
}

// HookWatchFile is a hook for watching file changes, for platforms that support it.
// The function is called with a directory and filename to watch, and a callback
// to call when the file changes. It returns an error if the watch could not be set up.
var HookWatchFile feature.Hook[func(ctx context.Context, dir, filename string, cb func()) error]

func (m *directManager) runFileWatcher() {
	watchFile, ok := HookWatchFile.GetOk()
	if !ok {
		return
	}
	if err := watchFile(m.ctx, "/etc/", resolvConf, m.checkForFileTrample); err != nil {
		// This is all best effort for now, so surface warnings to users.
		m.logf("dns: inotify: %s", err)
	}
}

var resolvTrampleWarnable = health.Register(&health.Warnable{
	Code:     "resolv-conf-overwritten",
	Severity: health.SeverityMedium,
	Title:    "DNS configuration issue",
	Text:     health.StaticMessage("System DNS config not ideal. /etc/resolv.conf overwritten. See https://tailscale.com/s/dns-fight"),
})

// checkForFileTrample checks whether /etc/resolv.conf has been trampled
// by another program on the system. (e.g. a DHCP client)
func (m *directManager) checkForFileTrample() {
	m.mu.Lock()
	want := m.wantResolvConf
	lastWarn := m.lastWarnContents
	m.mu.Unlock()

	if want == nil {
		return
	}

	cur, err := m.fs.ReadFile(resolvConf)
	if err != nil {
		m.logf("trample: read error: %v", err)
		return
	}
	if bytes.Equal(cur, want) {
		m.health.SetHealthy(resolvTrampleWarnable)
		if lastWarn != nil {
			m.mu.Lock()
			m.lastWarnContents = nil
			m.mu.Unlock()
			m.logf("trample: resolv.conf again matches expected content")
		}
		return
	}
	if bytes.Equal(cur, lastWarn) {
		// We already logged about this, so not worth doing it again.
		return
	}

	m.mu.Lock()
	m.lastWarnContents = cur
	m.mu.Unlock()

	show := cur
	if len(show) > 1024 {
		show = show[:1024]
	}
	m.logf("trample: resolv.conf changed from what we expected. did some other program interfere? current contents: %q", show)
	m.health.SetUnhealthy(resolvTrampleWarnable, nil)
}

func (m *directManager) Close() error {
	m.ctxClose()

	// We used to keep a file for the tailscale config and symlinked
	// to it, but then we stopped because /etc/resolv.conf being a
	// symlink to surprising places breaks snaps and other sandboxing
	// things. Clean it up if it's still there.
	m.fs.Remove("/etc/resolv.tailscale.conf")

	if _, err := m.fs.Stat(backupConf); err != nil {
		if os.IsNotExist(err) {
			// No backup, nothing we can do.
			return nil
		}
		return err
	}
	owned, err := m.ownedByTailscale()
	if err != nil {
		return err
	}
	_, err = m.fs.Stat(resolvConf)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	resolvConfExists := !os.IsNotExist(err)

	if resolvConfExists && !owned {
		// There's already a non-tailscale config in place, get rid of
		// our backup.
		m.fs.Remove(backupConf)
		return nil
	}

	// We own resolv.conf, and a backup exists.
	if err := m.rename(backupConf, resolvConf); err != nil {
		return err
	}

	if isResolvedRunning() && !runningAsGUIDesktopUser() {
		m.logf("restarting systemd-resolved...")
		if err := restartResolved(); err != nil {
			m.logf("restart of systemd-resolved failed: %v", err)
		} else {
			m.logf("restarted systemd-resolved")
		}
	}

	return nil
}

func (m *directManager) atomicWriteFile(fs wholeFileFS, filename string, data []byte, perm os.FileMode) error {
	var randBytes [12]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return fmt.Errorf("atomicWriteFile: %w", err)
	}

	tmpName := fmt.Sprintf("%s.%x.tmp", filename, randBytes[:])
	defer fs.Remove(tmpName)

	if err := fs.WriteFile(tmpName, data, perm); err != nil {
		return fmt.Errorf("atomicWriteFile: %w", err)
	}
	// Explicitly set the permissions on the temporary file before renaming
	// it. This ensures that if we have a umask set which prevents creating
	// world-readable files, the file will still have the correct
	// permissions once it's renamed into place. See #12609.
	if err := fs.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("atomicWriteFile: Chmod: %w", err)
	}

	return m.rename(tmpName, filename)
}

// wholeFileFS is a high-level file system abstraction designed just for use
// by directManager, with the goal that it is easy to implement over wsl.exe.
//
// All name parameters are absolute paths.
type wholeFileFS interface {
	Chmod(name string, mode os.FileMode) error
	ReadFile(name string) ([]byte, error)
	Remove(name string) error
	Rename(oldName, newName string) error
	Stat(name string) (isRegular bool, err error)
	Truncate(name string) error
	WriteFile(name string, contents []byte, perm os.FileMode) error
}

// directFS is a wholeFileFS implemented directly on the OS.
type directFS struct {
	// prefix is file path prefix.
	//
	// All name parameters are absolute paths so this is typically a
	// testing temporary directory like "/tmp".
	prefix string
}

func (fs directFS) path(name string) string { return filepath.Join(fs.prefix, name) }

func (fs directFS) Stat(name string) (isRegular bool, err error) {
	fi, err := os.Stat(fs.path(name))
	if err != nil {
		return false, err
	}
	return fi.Mode().IsRegular(), nil
}

func (fs directFS) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(fs.path(name), mode)
}

func (fs directFS) Rename(oldName, newName string) error {
	return os.Rename(fs.path(oldName), fs.path(newName))
}

func (fs directFS) Remove(name string) error { return os.Remove(fs.path(name)) }

func (fs directFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(fs.path(name))
}

func (fs directFS) Truncate(name string) error {
	return os.Truncate(fs.path(name), 0)
}

func (fs directFS) WriteFile(name string, contents []byte, perm os.FileMode) error {
	return os.WriteFile(fs.path(name), contents, perm)
}

// runningAsGUIDesktopUser reports whether it seems that this code is
// being run as a regular user on a Linux desktop. This is a quick
// hack to fix Issue 2672 where PolicyKit pops up a GUI dialog asking
// to proceed we do a best effort attempt to restart
// systemd-resolved.service. There's surely a better way.
func runningAsGUIDesktopUser() bool {
	return os.Getuid() != 0 && os.Getenv("DISPLAY") != ""
}
