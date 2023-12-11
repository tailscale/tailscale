package impersonatingfs

import (
	"os/exec"
	"strings"
)

func getUID(filename string) (string, error) {
	out, err := exec.Command("stat", "-f", "%u", filename).Output()
	return strings.TrimSpace(string(out)), err
}

func getGID(filename string) (string, error) {
	out, err := exec.Command("stat", "-f", "%g", filename).Output()
	return strings.TrimSpace(string(out)), err
}
