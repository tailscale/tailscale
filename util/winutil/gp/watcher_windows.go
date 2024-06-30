// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package gp

import (
	"golang.org/x/sys/windows"
)

// ChangeWatcher calls the handler whenever a policy in the specified scope changes.
type ChangeWatcher struct {
	gpWaitEvents [2]windows.Handle
	handler      func()
	done         chan struct{}
}

// NewChangeWatcher creates an instance of ChangeWatcher that invokes handler
// every time Windows notifies it of a group policy change in the specified scope.
func NewChangeWatcher(scope Scope, handler func()) (*ChangeWatcher, error) {
	var err error

	// evtDone is signaled by (*gpNotificationWatcher).Close() to indicate that
	// the doWatch goroutine should exit.
	evtDone, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(evtDone)
		}
	}()

	// evtChanged is registered with the Windows policy engine to become
	// signalled any time group policy has been refreshed.
	evtChanged, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(evtChanged)
		}
	}()

	// Tell Windows to signal evtChanged whenever group policies are refreshed.
	if err := registerGPNotification(evtChanged, scope == MachinePolicy); err != nil {
		return nil, err
	}

	result := &ChangeWatcher{
		// Ordering of the event handles in gpWaitEvents is important:
		// When calling windows.WaitForMultipleObjects and multiple objects are
		// signalled simultaneously, it always returns the wait code for the
		// lowest-indexed handle in its input array. evtDone is higher priority for
		// us than evtChanged, so the former must be placed into the array ahead of
		// the latter.
		gpWaitEvents: [2]windows.Handle{
			evtDone,
			evtChanged,
		},
		handler: handler,
		done:    make(chan struct{}),
	}

	go result.doWatch()

	return result, nil
}

func (w *ChangeWatcher) doWatch() {
	// The wait code corresponding to the event that is signalled when a group
	// policy change occurs. That is, w.gpWaitEvents[1] aka evtChanged.
	const expectedWaitCode = windows.WAIT_OBJECT_0 + 1
	for {
		if waitCode, _ := windows.WaitForMultipleObjects(w.gpWaitEvents[:], false, windows.INFINITE); waitCode != expectedWaitCode {
			break
		}
		w.handler()
	}
	close(w.done)
}

// Close unsubscribes from further Group Policy notifications,
// waits for any running handlers to complete, and releases any remaining resources
// associated with w.
func (w *ChangeWatcher) Close() error {
	// Notify doWatch that we're done and it should exit.
	if err := windows.SetEvent(w.gpWaitEvents[0]); err != nil {
		return err
	}

	unregisterGPNotification(w.gpWaitEvents[1])

	// Wait for doWatch to complete.
	<-w.done

	// Now we may safely clean up all the things.
	for i, evt := range w.gpWaitEvents {
		windows.CloseHandle(evt)
		w.gpWaitEvents[i] = 0
	}

	w.handler = nil

	return nil
}
