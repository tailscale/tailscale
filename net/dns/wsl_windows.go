// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"

	"tailscale.com/types/logger"
)

func wslExists() bool {
	cmd := exec.Command("wsl.exe", "-l", "-q")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) != "" // linux is installed
}

type wslManager struct {
	logf logger.Logf
	m    directManager
}

func newWSLManager(logf logger.Logf) *wslManager {
	return &wslManager{
		logf: logf,
		m:    newDirectManagerOnFS(wslFS{user: "root"}),
	}
}

func (m wslManager) SetDNS(cfg OSConfig) error {
	if !cfg.IsZero() {
		changed, err := m.setWSLConf()
		if err != nil {
			m.logf("WSL SetDNS wsl.conf: %v", err)
		} else if changed {
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
				m.logf("WSL SetDNS shutdown: %v: %s", err, b)
			}
		}

		// TODO(crawshaw): use "ip r" to get the default gateway and
		// add it to the nameserver list. This is the default resolv.conf
		// entry for WSL2, and that way it gets used as a backup when
		// tailscale is off.
	}
	if err := m.m.SetDNS(cfg); err != nil {
		m.logf("WSL SetDNS: %v", err)
	}
	return nil
}

const wslConf = "/etc/wsl.conf"
const wslConfSection = `[network]
generateResolvConf = false  # added by tailscale
`

func (m wslManager) setWSLConf() (changed bool, err error) {
	b, err := m.m.fs.ReadFile(wslConf)
	m.logf("setWSLConf XXX b=%s, err=%v", b, err)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	ini := parseIni(string(b))
	m.logf("wsl.conf ini: %v", ini)
	if v := ini["network"]["generateResolvConf"]; v == "" {
		b = append(b, wslConfSection...)
		if err := m.m.fs.WriteFile(wslConf, b, 0644); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func parseIni(data string) map[string]map[string]string {
	sectionRE := regexp.MustCompile(`^\[([^]]+)\]\s*`)
	kvRE := regexp.MustCompile(`^\s*(\w*)\s*=\s*([^#]*)\s*`)

	ini := map[string]map[string]string{}
	var section string
	for _, line := range strings.Split(data, "\n") {
		if res := sectionRE.FindStringSubmatch(line); len(res) > 1 {
			section = res[1]
			ini[section] = map[string]string{}
		} else if res := kvRE.FindStringSubmatch(line); len(res) > 2 {
			k, v := res[1], res[2]
			ini[section][k] = v
		}
	}
	return ini
}

func (m wslManager) SupportsSplitDNS() bool { return false }
func (m wslManager) Close() error           { return m.SetDNS(OSConfig{}) }

// wslFS is a pinholeFS implemented on top of wsl.exe.
//
// We access WSL2 file systems via wsl.exe instead of \\wsl$\ because
// the netpath appears to operate as the standard user, not root.
type wslFS struct {
	user string
}

func (fs wslFS) Stat(name string) (isRegular bool, err error) {
	err = wslCommand("-u", fs.user, "-e", "test", "-f", name).Run()
	if ee, _ := err.(*exec.ExitError); ee != nil {
		if ee.ExitCode() == 1 {
			return false, os.ErrNotExist
		}
		return false, err
	}
	return true, nil
}

func (fs wslFS) Rename(oldName, newName string) error {
	return wslCommand("-u", fs.user, "-e", "mv", oldName, newName).Run()
}

func (fs wslFS) Symlink(oldName, newName string) error {
	return wslCommand("-u", fs.user, "-e", "ln", "-s", "-f", oldName, newName).Run()
}

func (fs wslFS) Remove(name string) error { return wslCommand("-u", fs.user, "-e", "rm", name).Run() }

func (fs wslFS) ReadFile(name string) ([]byte, error) {
	b, err := wslCommand("-u", fs.user, "-e", "cat", name).CombinedOutput()
	if ee, _ := err.(*exec.ExitError); ee != nil && ee.ExitCode() == 1 {
		return nil, os.ErrNotExist
	}
	return b, err
}

func (fs wslFS) WriteFile(name string, contents []byte, perm os.FileMode) error {
	cmd := wslCommand("-u", fs.user, "-e", "tee", name)
	cmd.Stdin = bytes.NewReader(contents)
	cmd.Stdout = nil
	if err := cmd.Run(); err != nil {
		return err
	}
	return wslCommand("-u", fs.user, "-e", "chmod", "0644", name).Run() // TODO perm
}

func wslCommand(args ...string) *exec.Cmd {
	cmd := exec.Command("wsl.exe", args...)
	fmt.Printf("wslCommand: %v\n", cmd.Args)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}
