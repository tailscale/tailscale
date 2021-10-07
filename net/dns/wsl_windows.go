// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"tailscale.com/types/logger"
	"tailscale.com/util/winutil"
)

// wslDistros reports the names of the installed WSL2 linux distributions.
func wslDistros() ([]string, error) {
	b, err := wslCombinedOutput(exec.Command("wsl.exe", "-l"))
	if err != nil {
		return nil, fmt.Errorf("%v: %q", err, string(b))
	}

	// The first line of output is a WSL header. E.g.
	//
	//	C:\tsdev>wsl.exe -l
	//	Windows Subsystem for Linux Distributions:
	//	Ubuntu-20.04 (Default)
	//
	// We can skip it by passing '-q', but here we put it to work.
	// It turns out wsl.exe -l is broken, and outputs UTF-16 names
	// that nothing can read. (Try `wsl.exe -l | more`.)
	// So we look at the header to see if it's UTF-16.
	// If so, we run the rest through a UTF-16 parser.
	//
	// https://github.com/microsoft/WSL/issues/4607
	var output string
	if bytes.HasPrefix(b, []byte("W\x00i\x00n\x00d\x00o\x00w\x00s\x00")) {
		output, err = decodeUTF16(b)
		if err != nil {
			return nil, fmt.Errorf("failed to decode wsl.exe -l output %q: %v", b, err)
		}
	} else {
		output = string(b)
	}
	lines := strings.Split(output, "\n")
	if len(lines) < 1 {
		return nil, nil
	}
	lines = lines[1:] // drop "Windows Subsystem For Linux" header

	var distros []string
	for _, name := range lines {
		name = strings.TrimSpace(name)
		name = strings.TrimSuffix(name, " (Default)")
		if name == "" {
			continue
		}
		distros = append(distros, name)
	}
	return distros, nil
}

func decodeUTF16(b []byte) (string, error) {
	if len(b) == 0 {
		return "", nil
	} else if len(b)%2 != 0 {
		return "", fmt.Errorf("decodeUTF16: invalid length %d", len(b))
	}
	var u16 []uint16
	for i := 0; i < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])+(uint16(b[i+1])<<8))
	}
	return string(utf16.Decode(u16)), nil
}

// wslManager is a DNS manager for WSL2 linux distributions.
// It configures /etc/wsl.conf and /etc/resolv.conf.
type wslManager struct {
	logf logger.Logf
}

func newWSLManager(logf logger.Logf) *wslManager {
	m := &wslManager{
		logf: logf,
	}
	return m
}

func (wm *wslManager) SetDNS(cfg OSConfig) error {
	distros, err := wslDistros()
	if err != nil {
		return err
	} else if len(distros) == 0 {
		return nil
	}
	managers := make(map[string]*directManager)
	for _, distro := range distros {
		managers[distro] = newDirectManagerOnFS(wm.logf, wslFS{
			user:   "root",
			distro: distro,
		})
	}

	if !cfg.IsZero() {
		if wm.setWSLConf(managers) {
			// What's this? So glad you asked.
			//
			// WSL2 writes the /etc/resolv.conf.
			// It is aggressive about it. Every time you execute wsl.exe,
			// it writes it. (Opening a terminal is done by running wsl.exe.)
			// You can turn this off using /etc/wsl.conf! But: this wsl.conf
			// file is only parsed when the VM boots up. To do that, we
			// have to shut down WSL2.
			//
			// So we do it here, before we call wsl.exe to write resolv.conf.
			if b, err := wslCombinedOutput(wslCommand("--shutdown")); err != nil {
				wm.logf("WSL SetDNS shutdown: %v: %s", err, b)
			}
		}
	}

	for distro, m := range managers {
		if err := m.SetDNS(cfg); err != nil {
			wm.logf("WSL(%q) SetDNS: %v", distro, err)
		}
	}
	return nil
}

const wslConf = "/etc/wsl.conf"
const wslConfSection = `# added by tailscale
[network]
generateResolvConf = false
`

// setWSLConf attempts to disable generateResolvConf in each WSL2 linux.
// If any are changed, it reports true.
func (wm *wslManager) setWSLConf(managers map[string]*directManager) (changed bool) {
	for distro, m := range managers {
		b, err := m.fs.ReadFile(wslConf)
		if err != nil && !os.IsNotExist(err) {
			wm.logf("WSL(%q) wsl.conf: read: %v", distro, err)
			continue
		}
		ini := parseIni(string(b))
		if v := ini["network"]["generateResolvConf"]; v == "" {
			b = append(b, wslConfSection...)
			if err := m.fs.WriteFile(wslConf, b, 0644); err != nil {
				wm.logf("WSL(%q) wsl.conf: write: %v", distro, err)
				continue
			}
			changed = true
		}
	}
	return changed
}

func (m *wslManager) SupportsSplitDNS() bool { return false }
func (m *wslManager) Close() error           { return m.SetDNS(OSConfig{}) }

// wslFS is a pinholeFS implemented on top of wsl.exe.
//
// We access WSL2 file systems via wsl.exe instead of \\wsl$\ because
// the netpath appears to operate as the standard user, not root.
type wslFS struct {
	user   string
	distro string
}

func (fs wslFS) Stat(name string) (isRegular bool, err error) {
	err = wslRun(fs.cmd("test", "-f", name))
	if ee, _ := err.(*exec.ExitError); ee != nil {
		if ee.ExitCode() == 1 {
			return false, os.ErrNotExist
		}
		return false, err
	}
	return true, nil
}

func (fs wslFS) Rename(oldName, newName string) error {
	return wslRun(fs.cmd("mv", "--", oldName, newName))
}
func (fs wslFS) Remove(name string) error { return wslRun(fs.cmd("rm", "--", name)) }

func (fs wslFS) Truncate(name string) error { return fs.WriteFile(name, nil, 0644) }

func (fs wslFS) ReadFile(name string) ([]byte, error) {
	b, err := wslCombinedOutput(fs.cmd("cat", "--", name))
	if ee, _ := err.(*exec.ExitError); ee != nil && ee.ExitCode() == 1 {
		return nil, os.ErrNotExist
	}
	return b, err
}

func (fs wslFS) WriteFile(name string, contents []byte, perm os.FileMode) error {
	cmd := fs.cmd("tee", "--", name)
	cmd.Stdin = bytes.NewReader(contents)
	cmd.Stdout = nil
	if err := wslRun(cmd); err != nil {
		return err
	}
	return wslRun(fs.cmd("chmod", "--", fmt.Sprintf("%04o", perm), name))
}

func (fs wslFS) cmd(args ...string) *exec.Cmd {
	cmd := wslCommand("-u", fs.user, "-d", fs.distro, "-e")
	cmd.Args = append(cmd.Args, args...)
	return cmd
}

func wslCommand(args ...string) *exec.Cmd {
	cmd := exec.Command("wsl.exe", args...)
	return cmd
}

func wslCombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	cmd.Stderr = buf
	err := wslRun(cmd)
	return buf.Bytes(), err
}

func wslRun(cmd *exec.Cmd) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("wslRun(%v): %w", cmd.Args, err)
		}
	}()

	var token windows.Token
	if u, err := user.Current(); err == nil && u.Name == "SYSTEM" {
		// We need to switch user to run wsl.exe.
		// https://github.com/microsoft/WSL/issues/4803
		sessionID := winutil.WTSGetActiveConsoleSessionId()
		if sessionID != 0xFFFFFFFF {
			if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
				return err
			}
			defer token.Close()
		}
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:      syscall.Token(token),
		HideWindow: true,
	}
	return cmd.Run()
}
