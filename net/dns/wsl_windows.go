// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unicode/utf16"

	"tailscale.com/types/logger"
)

// wslDistros reports the names of the installed WSL2 linux distributions.
func wslDistros(logf logger.Logf) []string {
	cmd := exec.Command("wsl.exe", "-l")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, err := cmd.CombinedOutput()
	if err != nil {
		return nil
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
			logf("failed to decode wsl.exe -l output %q: %v", b, err)
			return nil
		}
	} else {
		output = string(b)
	}
	fmt.Printf("wslDistros: %q\n", output)
	lines := strings.Split(output, "\n")
	if len(lines) < 1 {
		return nil
	}
	lines = lines[1:] // drop "Windows Subsystem For Linux" header

	var distros []string
	for _, name := range lines {
		name = strings.TrimSpace(name)
		name = strings.TrimSuffix(name, " (Default)")
		if name == "" {
			continue
		}
		fmt.Printf("wslDistros: name=%q\n", name)
		distros = append(distros, name)
	}
	return distros
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
	logf     logger.Logf
	managers map[string]directManager // distro name -> manager
}

func newWSLManager(logf logger.Logf, distros []string) *wslManager {
	m := &wslManager{
		logf:     logf,
		managers: make(map[string]directManager),
	}
	for _, distro := range distros {
		m.managers[distro] = newDirectManagerOnFS(wslFS{
			user:   "root",
			distro: distro,
		})
	}
	return m
}

func (wm *wslManager) SetDNS(cfg OSConfig) error {
	if !cfg.IsZero() {
		if wm.setWSLConf() {
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
			if b, err := wslCommand("--shutdown").CombinedOutput(); err != nil {
				wm.logf("WSL SetDNS shutdown: %v: %s", err, b)
			}
		}
	}

	for distro, m := range wm.managers {
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
func (wm *wslManager) setWSLConf() (changed bool) {
	for distro, m := range wm.managers {
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
	err = fs.cmd("test", "-f", name).Run()
	if ee, _ := err.(*exec.ExitError); ee != nil {
		if ee.ExitCode() == 1 {
			return false, os.ErrNotExist
		}
		return false, err
	}
	return true, nil
}

func (fs wslFS) Rename(oldName, newName string) error {
	return fs.cmd("mv", "--", oldName, newName).Run()
}
func (fs wslFS) Remove(name string) error { return fs.cmd("rm", "--", name).Run() }

func (fs wslFS) ReadFile(name string) ([]byte, error) {
	b, err := fs.cmd("cat", "--", name).CombinedOutput()
	if ee, _ := err.(*exec.ExitError); ee != nil && ee.ExitCode() == 1 {
		return nil, os.ErrNotExist
	}
	return b, err
}

func (fs wslFS) WriteFile(name string, contents []byte, perm os.FileMode) error {
	cmd := fs.cmd("tee", "--", name)
	cmd.Stdin = bytes.NewReader(contents)
	cmd.Stdout = nil
	if err := cmd.Run(); err != nil {
		return err
	}
	return fs.cmd("chmod", "--", fmt.Sprintf("%04o", perm), name).Run()
}

func (fs wslFS) cmd(args ...string) *exec.Cmd {
	cmd := wslCommand("-u", fs.user, "-d", fs.distro, "-e")
	cmd.Args = append(cmd.Args, args...)
	fmt.Printf("wslFS.cmd: %v\n", cmd.Args)
	return cmd
}

func wslCommand(args ...string) *exec.Cmd {
	cmd := exec.Command("wsl.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}
