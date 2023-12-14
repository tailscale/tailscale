//go:build windows

package runas

import (
	"fmt"
	"os/exec"
)

func Cmd(username string, executable string, args ...string) *exec.Cmd {
	allArgs := []string{fmt.Sprintf("/user:", username), executable}
	allArgs = append(allArgs, args...)
	return exec.Command("runas", allArgs...)
}
