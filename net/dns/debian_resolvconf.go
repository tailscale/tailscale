// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || freebsd || openbsd

package dns

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"tailscale.com/atomicfile"
	"tailscale.com/types/logger"
)

//go:embed resolvconf-workaround.sh
var workaroundScript []byte

// resolvconfConfigName is the name of the config submitted to
// resolvconf.
// The name starts with 'tun' in order to match the hardcoded
// interface order in debian resolvconf, which will place this
// configuration ahead of regular network links. In theory, this
// doesn't matter because we then fix things up to ensure our config
// is the only one in use, but in case that fails, this will make our
// configuration slightly preferred.
// The 'inet' suffix has no specific meaning, but conventionally
// resolvconf implementations encourage adding a suffix roughly
// indicating where the config came from, and "inet" is the "none of
// the above" value (rather than, say, "ppp" or "dhcp").
const resolvconfConfigName = "tun-tailscale.inet"

// resolvconfLibcHookPath is the directory containing libc update
// scripts, which are run by Debian resolvconf when /etc/resolv.conf
// has been updated.
const resolvconfLibcHookPath = "/etc/resolvconf/update-libc.d"

// resolvconfHookPath is the name of the libc hook script we install
// to force Tailscale's DNS config to take effect.
var resolvconfHookPath = filepath.Join(resolvconfLibcHookPath, "tailscale")

// resolvconfManager manages DNS configuration using the Debian
// implementation of the `resolvconf` program, written by Thomas Hood.
type resolvconfManager struct {
	logf            logger.Logf
	listRecordsPath string
	interfacesDir   string
	scriptInstalled bool // libc update script has been installed
}

func newDebianResolvconfManager(logf logger.Logf) (*resolvconfManager, error) {
	ret := &resolvconfManager{
		logf:            logf,
		listRecordsPath: "/lib/resolvconf/list-records",
		interfacesDir:   "/etc/resolvconf/run/interface", // panic fallback if nothing seems to work
	}

	if _, err := os.Stat(ret.listRecordsPath); os.IsNotExist(err) {
		// This might be a Debian system from before the big /usr
		// merge, try /usr instead.
		ret.listRecordsPath = "/usr" + ret.listRecordsPath
	}
	// The runtime directory is currently (2020-04) canonically
	// /etc/resolvconf/run, but the manpage is making noise about
	// switching to /run/resolvconf and dropping the /etc path. So,
	// let's probe the possible directories and use the first one
	// that works.
	for _, path := range []string{
		"/etc/resolvconf/run/interface",
		"/run/resolvconf/interface",
		"/var/run/resolvconf/interface",
	} {
		if _, err := os.Stat(path); err == nil {
			ret.interfacesDir = path
			break
		}
	}
	if ret.interfacesDir == "" {
		// None of the paths seem to work, use the canonical location
		// that the current manpage says to use.
		ret.interfacesDir = "/etc/resolvconf/run/interfaces"
	}

	return ret, nil
}

func (m *resolvconfManager) deleteTailscaleConfig() error {
	cmd := exec.Command("resolvconf", "-d", resolvconfConfigName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("running %s: %s", cmd, out)
	}
	return nil
}

func (m *resolvconfManager) SetDNS(config OSConfig) error {
	if !m.scriptInstalled {
		m.logf("injecting resolvconf workaround script")
		if err := os.MkdirAll(resolvconfLibcHookPath, 0755); err != nil {
			return err
		}
		if err := atomicfile.WriteFile(resolvconfHookPath, workaroundScript, 0755); err != nil {
			return err
		}
		m.scriptInstalled = true
	}

	if config.IsZero() {
		if err := m.deleteTailscaleConfig(); err != nil {
			return err
		}
	} else {
		stdin := new(bytes.Buffer)
		writeResolvConf(stdin, config.Nameservers, config.SearchDomains) // dns_direct.go

		// This resolvconf implementation doesn't support exclusive
		// mode or interface priorities, so it will end up blending
		// our configuration with other sources. However, this will
		// get fixed up by the script we injected above.
		cmd := exec.Command("resolvconf", "-a", resolvconfConfigName)
		cmd.Stdin = stdin
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("running %s: %s", cmd, out)
		}
	}

	return nil
}

func (m *resolvconfManager) SupportsSplitDNS() bool {
	return false
}

func (m *resolvconfManager) GetBaseConfig() (OSConfig, error) {
	var bs bytes.Buffer

	cmd := exec.Command(m.listRecordsPath)
	// list-records assumes it's being run with CWD set to the
	// interfaces runtime dir, and returns nonsense otherwise.
	cmd.Dir = m.interfacesDir
	cmd.Stdout = &bs
	if err := cmd.Run(); err != nil {
		return OSConfig{}, err
	}

	var conf bytes.Buffer
	sc := bufio.NewScanner(&bs)
	for sc.Scan() {
		if sc.Text() == resolvconfConfigName {
			continue
		}
		bs, err := os.ReadFile(filepath.Join(m.interfacesDir, sc.Text()))
		if err != nil {
			if os.IsNotExist(err) {
				// Probably raced with a deletion, that's okay.
				continue
			}
			return OSConfig{}, err
		}
		conf.Write(bs)
		conf.WriteByte('\n')
	}

	return readResolv(&conf)
}

func (m *resolvconfManager) Close() error {
	if err := m.deleteTailscaleConfig(); err != nil {
		return err
	}

	if m.scriptInstalled {
		m.logf("removing resolvconf workaround script")
		os.Remove(resolvconfHookPath) // Best-effort
	}

	return nil
}
