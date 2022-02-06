// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"os"
	"sync"
	"syscall"
)

const (
	// In earlier versions of iptables, the xtables lock was implemented
	// via a Unix socket, but now flock is used via this lockfile:
	// http://git.netfilter.org/iptables/commit/?id=aa562a660d1555b13cffbac1e744033e91f82707
	// Note the LSB-conforming "/run" directory does not exist on old
	// distributions, so assume "/var" is symlinked
	xtablesLockFilePath = "/var/run/xtables.lock"

	defaultFilePerm = 0600
)

type Unlocker interface {
	Unlock() error
}

type nopUnlocker struct{}

func (_ nopUnlocker) Unlock() error { return nil }

type fileLock struct {
	// mu is used to protect against concurrent invocations from within this process
	mu sync.Mutex
	fd int
}

// tryLock takes an exclusive lock on the xtables lock file without blocking.
// This is best-effort only: if the exclusive lock would block (i.e. because
// another process already holds it), no error is returned. Otherwise, any
// error encountered during the locking operation is returned.
// The returned Unlocker should be used to release the lock when the caller is
// done invoking iptables commands.
func (l *fileLock) tryLock() (Unlocker, error) {
	l.mu.Lock()
	err := syscall.Flock(l.fd, syscall.LOCK_EX|syscall.LOCK_NB)
	switch err {
	case syscall.EWOULDBLOCK:
		l.mu.Unlock()
		return nopUnlocker{}, nil
	case nil:
		return l, nil
	default:
		l.mu.Unlock()
		return nil, err
	}
}

// Unlock closes the underlying file, which implicitly unlocks it as well. It
// also unlocks the associated mutex.
func (l *fileLock) Unlock() error {
	defer l.mu.Unlock()
	return syscall.Close(l.fd)
}

// newXtablesFileLock opens a new lock on the xtables lockfile without
// acquiring the lock
func newXtablesFileLock() (*fileLock, error) {
	fd, err := syscall.Open(xtablesLockFilePath, os.O_CREATE, defaultFilePerm)
	if err != nil {
		return nil, err
	}
	return &fileLock{fd: fd}, nil
}
