// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package gp

import (
	"errors"
	"sync"
	"testing"
	"time"

	"tailscale.com/util/cibuild"
)

func TestWatchForPolicyChange(t *testing.T) {
	if cibuild.On() {
		// Unlike tests that also use the GP API in net\dns\manager_windows_test.go,
		// this one does not require elevation. However, a Group Policy change notification
		// never arrives when this tests runs on a GitHub-hosted runner.
		t.Skipf("test requires running on a real Windows environment")
	}

	done, close := setupMachinePolicyChangeNotifier(t)
	defer close()

	// RefreshMachinePolicy is a non-blocking call.
	if err := RefreshMachinePolicy(true); err != nil {
		t.Fatalf("RefreshMachinePolicy failed: %v", err)
	}

	// We should receive a policy change notification when
	// the Group Policy service completes policy processing.
	// Otherwise, the test will eventually time out.
	<-done
}

func TestGroupPolicyReadLock(t *testing.T) {
	if cibuild.On() {
		// Unlike tests that also use the GP API in net\dns\manager_windows_test.go,
		// this one does not require elevation. However, a Group Policy change notification
		// never arrives when this tests runs on a GitHub-hosted runner.
		t.Skipf("test requires running on a real Windows environment")
	}

	done, close := setupMachinePolicyChangeNotifier(t)
	defer close()

	doWithMachinePolicyLocked(t, func() {
		// RefreshMachinePolicy is a non-blocking call.
		if err := RefreshMachinePolicy(true); err != nil {
			t.Fatalf("RefreshMachinePolicy failed: %v", err)
		}

		// Give the Group Policy service a few seconds to attempt to refresh the policy.
		// It shouldn't be able to do so while the lock is held, and the below should time out.
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		select {
		case <-timeout.C:
		case <-done:
			t.Fatal("Policy refresh occurred while the policy lock was held")
		}
	})

	// We should receive a policy change notification once the lock is released
	// and GP can refresh the policy.
	// Otherwise, the test will eventually time out.
	<-done
}

func TestHammerGroupPolicyReadLock(t *testing.T) {
	const N = 10_000

	enter := func(bool) (policyLockHandle, error) { return 1, nil }
	leave := func(policyLockHandle) error { return nil }

	doWithCustomEnterLeaveFuncs(t, func(gpLock *PolicyLock) {
		var wg sync.WaitGroup
		wg.Add(N)
		for range N {
			go func() {
				defer wg.Done()
				if err := gpLock.Lock(); err != nil {
					t.Errorf("(*PolicyLock).Lock failed: %v", err)
					return
				}
				defer gpLock.Unlock()
				if gpLock.handle == 0 {
					t.Error("(*PolicyLock).handle is 0")
					return
				}
			}()
		}
		wg.Wait()
	}, enter, leave)
}

func TestGroupPolicyReadLockClose(t *testing.T) {
	init := make(chan struct{})
	enter := func(bool) (policyLockHandle, error) {
		close(init)
		time.Sleep(500 * time.Millisecond)
		return 1, nil
	}
	leave := func(policyLockHandle) error { return nil }

	doWithCustomEnterLeaveFuncs(t, func(gpLock *PolicyLock) {
		done := make(chan struct{})
		go func() {
			defer close(done)

			err := gpLock.Lock()
			if err == nil {
				defer gpLock.Unlock()
			}

			// We closed gpLock before the enter function returned.
			// (*PolicyLock).Lock is expected to fail.
			if err == nil || !errors.Is(err, ErrInvalidLockState) {
				t.Errorf("(*PolicyLock).Lock: got %v; want %v", err, ErrInvalidLockState)
			}
			// gpLock must not be held as Lock() failed.
			if lockCnt := gpLock.lockCnt.Load(); lockCnt != 0 {
				t.Errorf("lockCnt: got %v; want 0", lockCnt)
			}
		}()

		<-init
		// Close gpLock right before the enter function returns.
		if err := gpLock.Close(); err != nil {
			t.Fatalf("(*PolicyLock).Close failed: %v", err)
		}
		<-done
	}, enter, leave)
}

func TestGroupPolicyReadLockErr(t *testing.T) {
	wantErr := errors.New("failed to acquire the lock")

	enter := func(bool) (policyLockHandle, error) { return 0, wantErr }
	leave := func(policyLockHandle) error { t.Error("leaveCriticalPolicySection must not be called"); return nil }

	doWithCustomEnterLeaveFuncs(t, func(gpLock *PolicyLock) {
		err := gpLock.Lock()
		if err == nil {
			defer gpLock.Unlock()
		}
		if err != wantErr {
			t.Errorf("(*PolicyLock).Lock: got %v; want %v", err, wantErr)
		}
		// gpLock must not be held when Lock() fails.
		// The LSB indicates that the lock has not been closed.
		if lockCnt := gpLock.lockCnt.Load(); lockCnt&^(1) != 0 {
			t.Errorf("lockCnt: got %v; want 0", lockCnt)
		}
	}, enter, leave)
}

func setupMachinePolicyChangeNotifier(t *testing.T) (chan struct{}, func()) {
	done := make(chan struct{})
	var watcher *ChangeWatcher
	watcher, err := NewChangeWatcher(MachinePolicy, func() {
		close(done)
	})
	if err != nil {
		t.Fatalf("NewChangeWatcher failed: %v", err)
	}
	return done, func() {
		if err := watcher.Close(); err != nil {
			t.Errorf("(*ChangeWatcher).Close failed: %v", err)
		}
	}
}

func doWithMachinePolicyLocked(t *testing.T, f func()) {
	gpLock := NewMachinePolicyLock()
	defer gpLock.Close()
	if err := gpLock.Lock(); err != nil {
		t.Fatalf("(*PolicyLock).Lock failed: %v", err)
	}
	defer gpLock.Unlock()
	f()
}

func doWithCustomEnterLeaveFuncs(t *testing.T, f func(*PolicyLock), enter func(bool) (policyLockHandle, error), leave func(policyLockHandle) error) {
	t.Helper()

	lock := NewMachinePolicyLock()
	lock.enterFn, lock.leaveFn = enter, leave
	t.Cleanup(func() {
		if err := lock.Close(); err != nil {
			t.Fatalf("(*PolicyLock).Close failed: %v", err)
		}
	})

	f(lock)
}
