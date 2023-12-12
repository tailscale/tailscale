// package impersonatingfs provides an implementation of webdav.FileSystem that
// acts as a specific user and group, irrespective of what user the current
// process is running as. It works on Windows and UNIX operating systems.
package impersonatingfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/net/webdav"
)

type fs struct {
	base  string
	user  string
	group string
}

// New returns a new webdav.FileSystem that acts as the given user and group.
// On UNIX platforms, user and group should be numeric user and group IDs.
// On
func New(base, user, group string) webdav.FileSystem {
	return &fs{base: base, user: user, group: group}
}

func (fs *fs) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	path := filepath.Join(fs.base, name)

	// make sure user has write permissions to parent folder
	parent := filepath.Dir(path)
	if !hasWrite(parent, fs.user, fs.group) {
		return os.ErrPermission
	}

	// make the directory
	err := os.Mkdir(path, perm)
	if err != nil {
		return err
	}

	// change owner to the correct user and group
	return chown(path, fs.user, fs.group)
}

func (fs *fs) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	path := filepath.Join(fs.base, name)

	fi, err := os.Stat(path)
	fileExists := err == nil || !os.IsNotExist(err)
	if err != nil && fileExists {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	isWrite := hasFlag(flag, os.O_WRONLY) || hasFlag(flag, os.O_RDWR)
	if isWrite {
		if fileExists {
			// make sure user has write permissions to file
			if !hasWrite(path, fs.user, fs.group) {
				return nil, os.ErrPermission
			}
		} else {
			// make sure user has write permissions to parent directory
			parent := filepath.Dir(path)
			if !hasWrite(parent, fs.user, fs.group) {
				return nil, os.ErrPermission
			}
		}
	} else {
		if fileExists {
			if fi.IsDir() {
				// make sure user has execute permissions to file
				if !hasExecute(path, fs.user, fs.group) {
					return nil, os.ErrPermission
				}
			} else {
				// make sure user has read permissions to file
				if !hasRead(path, fs.user, fs.group) {
					return nil, os.ErrPermission
				}
			}
		}
	}

	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	err = f.Sync()
	if err != nil {
		return nil, err
	}

	if !fileExists {
		err = chown(path, fs.user, fs.group)
	}
	return f, err
}

func (fs *fs) RemoveAll(ctx context.Context, name string) error {
	path := filepath.Join(fs.base, name)

	if !hasWrite(path, fs.user, fs.group) {
		return os.ErrPermission
	}
	return os.RemoveAll(path)
}

func (fs *fs) Rename(ctx context.Context, oldName, newName string) error {
	oldPath := filepath.Join(fs.base, oldName)
	newPath := filepath.Join(fs.base, newName)

	if !hasWrite(oldPath, fs.user, fs.group) {
		return os.ErrPermission
	}
	parentOfNew := filepath.Dir(newPath)
	if !hasWrite(parentOfNew, fs.user, fs.group) {
		return os.ErrPermission
	}
	err := os.Rename(oldPath, newPath)
	if err != nil {
		return fmt.Errorf("rename %v to %v: %w", oldPath, newPath, err)
	}
	return chown(newPath, fs.user, fs.group)
}

func (fs *fs) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	// TODO(oxtoacart): translate permissions based on current user and actual owner
	return os.Stat(filepath.Join(fs.base, name))
}

func hasFlag(flags int, flag int) bool {
	return (flags & flag) == flag
}
