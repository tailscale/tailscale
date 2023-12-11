package impersonatingfs

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

func hasRead(filename string, uid, gid string) bool {
	err := exec.Command("sudo", "-u", fmt.Sprintf("#%v", uid), "-g", fmt.Sprintf("#%v", gid), "test", "-r", filename).Run()
	return err == nil
}

func hasWrite(filename string, uid, gid string) bool {
	err := exec.Command("sudo", "-u", fmt.Sprintf("#%v", uid), "-g", fmt.Sprintf("#%v", gid), "test", "-w", filename).Run()
	return err == nil
}

func chmod(filename string, mode os.FileMode) error {
	return os.Chmod(filename, mode)
}

func chown(filename string, user string, group string) error {
	uid, err := strconv.Atoi(user)
	if err != nil {
		return fmt.Errorf("strconv user: %w", err)
	}
	gid, err := strconv.Atoi(group)
	if err != nil {
		return fmt.Errorf("strconv group: %w", err)
	}
	return os.Chown(filename, uid, gid)
}
