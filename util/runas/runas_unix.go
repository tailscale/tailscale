//go:build unix

package runas

import "os/exec"

func Cmd(username string, executable string, args ...string) *exec.Cmd {
	allArgs := []string{"-u", username, executable}
	allArgs = append(allArgs, args...)
	return exec.Command("sudo", allArgs...)
}
