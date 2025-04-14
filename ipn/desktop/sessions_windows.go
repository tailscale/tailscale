// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package desktop

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
)

// wtsManager is a [SessionManager] implementation for Windows.
type wtsManager struct {
	logf      logger.Logf
	ctx       context.Context // cancelled when the manager is closed
	ctxCancel context.CancelFunc

	initOnce func() error
	watcher  *sessionWatcher

	mu       sync.Mutex
	sessions map[SessionID]*wtsSession
	initCbs  set.HandleSet[SessionInitCallback]
	stateCbs set.HandleSet[SessionStateCallback]
}

// NewSessionManager returns a new [SessionManager] for the current platform,
func NewSessionManager(logf logger.Logf) (SessionManager, error) {
	ctx, ctxCancel := context.WithCancel(context.Background())
	m := &wtsManager{
		logf:      logf,
		ctx:       ctx,
		ctxCancel: ctxCancel,
		sessions:  make(map[SessionID]*wtsSession),
	}
	m.watcher = newSessionWatcher(m.ctx, m.logf, m.sessionEventHandler)

	m.initOnce = sync.OnceValue(func() error {
		if err := waitUntilWTSReady(m.ctx); err != nil {
			return fmt.Errorf("WTS is not ready: %w", err)
		}

		m.mu.Lock()
		defer m.mu.Unlock()
		if err := m.watcher.Start(); err != nil {
			return fmt.Errorf("failed to start session watcher: %w", err)
		}

		var err error
		m.sessions, err = enumerateSessions()
		return err // may be nil or non-nil
	})
	return m, nil
}

// Init implements [SessionManager].
func (m *wtsManager) Init() error {
	return m.initOnce()
}

// Sessions implements [SessionManager].
func (m *wtsManager) Sessions() (map[SessionID]*Session, error) {
	if err := m.initOnce(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	sessions := make(map[SessionID]*Session, len(m.sessions))
	for _, s := range m.sessions {
		sessions[s.id] = s.AsSession()
	}
	return sessions, nil
}

// RegisterInitCallback implements [SessionManager].
func (m *wtsManager) RegisterInitCallback(cb SessionInitCallback) (unregister func(), err error) {
	if err := m.initOnce(); err != nil {
		return nil, err
	}
	if cb == nil {
		return nil, errors.New("nil callback")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	handle := m.initCbs.Add(cb)

	// TODO(nickkhyl): enqueue callbacks in a separate goroutine?
	for _, s := range m.sessions {
		if cleanup := cb(s.AsSession()); cleanup != nil {
			s.cleanup = append(s.cleanup, cleanup)
		}
	}

	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.initCbs, handle)
	}, nil
}

// RegisterStateCallback implements [SessionManager].
func (m *wtsManager) RegisterStateCallback(cb SessionStateCallback) (unregister func(), err error) {
	if err := m.initOnce(); err != nil {
		return nil, err
	}
	if cb == nil {
		return nil, errors.New("nil callback")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	handle := m.stateCbs.Add(cb)

	// TODO(nickkhyl): enqueue callbacks in a separate goroutine?
	for _, s := range m.sessions {
		cb(s.AsSession())
	}

	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.stateCbs, handle)
	}, nil
}

func (m *wtsManager) sessionEventHandler(id SessionID, event uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch event {
	case windows.WTS_SESSION_LOGON:
		// The session may have been created after we started watching,
		// but before the initial enumeration was performed.
		// Do not create a new session if it already exists.
		if _, _, err := m.getOrCreateSessionLocked(id); err != nil {
			m.logf("[unexpected] getOrCreateSessionLocked(%d): %v", id, err)
		}
	case windows.WTS_SESSION_LOCK:
		if err := m.setSessionStatusLocked(id, BackgroundSession); err != nil {
			m.logf("[unexpected] setSessionStatusLocked(%d, BackgroundSession): %v", id, err)
		}
	case windows.WTS_SESSION_UNLOCK:
		if err := m.setSessionStatusLocked(id, ForegroundSession); err != nil {
			m.logf("[unexpected] setSessionStatusLocked(%d, ForegroundSession): %v", id, err)
		}
	case windows.WTS_SESSION_LOGOFF:
		if err := m.deleteSessionLocked(id); err != nil {
			m.logf("[unexpected] deleteSessionLocked(%d): %v", id, err)
		}
	}
}

func (m *wtsManager) getOrCreateSessionLocked(id SessionID) (_ *wtsSession, created bool, err error) {
	if s, ok := m.sessions[id]; ok {
		return s, false, nil
	}

	s, err := newWTSSession(id, ForegroundSession)
	if err != nil {
		return nil, false, err
	}
	m.sessions[id] = s

	session := s.AsSession()
	// TODO(nickkhyl): enqueue callbacks in a separate goroutine?
	for _, cb := range m.initCbs {
		if cleanup := cb(session); cleanup != nil {
			s.cleanup = append(s.cleanup, cleanup)
		}
	}
	for _, cb := range m.stateCbs {
		cb(session)
	}

	return s, true, err
}

func (m *wtsManager) setSessionStatusLocked(id SessionID, status SessionStatus) error {
	s, _, err := m.getOrCreateSessionLocked(id)
	if err != nil {
		return err
	}
	if s.status == status {
		return nil
	}

	s.status = status
	session := s.AsSession()
	// TODO(nickkhyl): enqueue callbacks in a separate goroutine?
	for _, cb := range m.stateCbs {
		cb(session)
	}
	return nil
}

func (m *wtsManager) deleteSessionLocked(id SessionID) error {
	s, ok := m.sessions[id]
	if !ok {
		return nil
	}

	s.status = ClosedSession
	session := s.AsSession()
	// TODO(nickkhyl): enqueue callbacks (and [wtsSession.close]!) in a separate goroutine?
	for _, cb := range m.stateCbs {
		cb(session)
	}

	delete(m.sessions, id)
	return s.close()
}

func (m *wtsManager) Close() error {
	m.ctxCancel()

	if m.watcher != nil {
		err := m.watcher.Stop()
		if err != nil {
			return err
		}
		m.watcher = nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.initCbs = nil
	m.stateCbs = nil
	errs := make([]error, 0, len(m.sessions))
	for _, s := range m.sessions {
		errs = append(errs, s.close())
	}
	m.sessions = nil
	return errors.Join(errs...)
}

type wtsSession struct {
	id   SessionID
	user *ipnauth.WindowsActor

	status SessionStatus

	cleanup []func()
}

func newWTSSession(id SessionID, status SessionStatus) (*wtsSession, error) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(uint32(id), &token); err != nil {
		return nil, err
	}
	user, err := ipnauth.NewWindowsActorWithToken(token)
	if err != nil {
		return nil, err
	}
	return &wtsSession{id, user, status, nil}, nil
}

// enumerateSessions returns a map of all active WTS sessions.
func enumerateSessions() (map[SessionID]*wtsSession, error) {
	const reserved, version uint32 = 0, 1
	var numSessions uint32
	var sessionInfos *windows.WTS_SESSION_INFO
	if err := windows.WTSEnumerateSessions(_WTS_CURRENT_SERVER_HANDLE, reserved, version, &sessionInfos, &numSessions); err != nil {
		return nil, fmt.Errorf("WTSEnumerateSessions failed: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessionInfos)))

	sessions := make(map[SessionID]*wtsSession, numSessions)
	for _, si := range unsafe.Slice(sessionInfos, numSessions) {
		status := _WTS_CONNECTSTATE_CLASS(si.State).ToSessionStatus()
		if status == ClosedSession {
			// The session does not exist as far as we're concerned.
			// It may be in the process of being created or destroyed,
			// or be a special "listener" session, etc.
			continue
		}
		id := SessionID(si.SessionID)
		session, err := newWTSSession(id, status)
		if err != nil {
			continue
		}
		sessions[id] = session
	}
	return sessions, nil
}

func (s *wtsSession) AsSession() *Session {
	return &Session{
		ID:     s.id,
		Status: s.status,
		// wtsSession owns the user; don't let the caller close it
		User: ipnauth.WithoutClose(s.user),
	}
}

func (m *wtsSession) close() error {
	for _, cleanup := range m.cleanup {
		cleanup()
	}
	m.cleanup = nil

	if m.user != nil {
		if err := m.user.Close(); err != nil {
			return err
		}
		m.user = nil
	}
	return nil
}

type sessionEventHandler func(id SessionID, event uint32)

// TODO(nickkhyl): implement a sessionWatcher that does not use the message queue.
// One possible approach is to have the tailscaled service register a HandlerEx function
// and stream SERVICE_CONTROL_SESSIONCHANGE events to the tailscaled subprocess
// (the actual tailscaled backend), exposing these events via [sessionWatcher]/[wtsManager].
//
// See tailscale/corp#26477 for details and tracking.
type sessionWatcher struct {
	logf      logger.Logf
	ctx       context.Context     // canceled to stop the watcher
	ctxCancel context.CancelFunc  // cancels the watcher
	hWnd      windows.HWND        // window handle for receiving session change notifications
	handler   sessionEventHandler // called on session events

	mu     sync.Mutex
	doneCh chan error // written to when the watcher exits; nil if not started
}

func newSessionWatcher(ctx context.Context, logf logger.Logf, handler sessionEventHandler) *sessionWatcher {
	ctx, cancel := context.WithCancel(ctx)
	return &sessionWatcher{logf: logf, ctx: ctx, ctxCancel: cancel, handler: handler}
}

func (sw *sessionWatcher) Start() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	select {
	case <-sw.ctx.Done():
		return fmt.Errorf("sessionWatcher already stopped: %w", sw.ctx.Err())
	default:
	}

	if sw.doneCh != nil {
		// Already started.
		return nil
	}
	sw.doneCh = make(chan error, 1)

	startedCh := make(chan error, 1)
	go sw.run(startedCh, sw.doneCh)
	if err := <-startedCh; err != nil {
		return err
	}

	// Signal the window to unsubscribe from session notifications
	// and shut down gracefully when the sessionWatcher is stopped.
	context.AfterFunc(sw.ctx, func() {
		sendMessage(sw.hWnd, _WM_CLOSE, 0, 0)
	})
	return nil
}

func (sw *sessionWatcher) run(started, done chan<- error) {
	runtime.LockOSThread()
	defer func() {
		runtime.UnlockOSThread()
		close(done)
	}()
	err := sw.createMessageWindow()
	started <- err
	if err != nil {
		return
	}
	pumpThreadMessages()
}

// Stop stops the session watcher and waits for it to exit.
func (sw *sessionWatcher) Stop() error {
	sw.ctxCancel()

	sw.mu.Lock()
	doneCh := sw.doneCh
	sw.doneCh = nil
	sw.mu.Unlock()

	if doneCh != nil {
		return <-doneCh
	}
	return nil
}

const watcherWindowClassName = "Tailscale-SessionManager"

var watcherWindowClassName16 = sync.OnceValue(func() *uint16 {
	return must.Get(syscall.UTF16PtrFromString(watcherWindowClassName))
})

var registerSessionManagerWindowClass = sync.OnceValue(func() error {
	var hInst windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &hInst); err != nil {
		return fmt.Errorf("GetModuleHandle: %w", err)
	}
	wc := _WNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(_WNDCLASSEX{})),
		HInstance:     hInst,
		LpfnWndProc:   syscall.NewCallback(sessionWatcherWndProc),
		LpszClassName: watcherWindowClassName16(),
	}
	if _, err := registerClassEx(&wc); err != nil {
		return fmt.Errorf("RegisterClassEx(%q): %w", watcherWindowClassName, err)
	}
	return nil
})

func (sw *sessionWatcher) createMessageWindow() error {
	if err := registerSessionManagerWindowClass(); err != nil {
		return err
	}
	_, err := createWindowEx(
		0,                          // dwExStyle
		watcherWindowClassName16(), // lpClassName
		nil,                        // lpWindowName
		0,                          // dwStyle
		0,                          // x
		0,                          // y
		0,                          // nWidth
		0,                          // nHeight
		_HWND_MESSAGE,              // hWndParent; message-only window
		0,                          // hMenu
		0,                          // hInstance
		unsafe.Pointer(sw),         // lpParam
	)
	if err != nil {
		return fmt.Errorf("CreateWindowEx: %w", err)
	}
	return nil
}

func (sw *sessionWatcher) wndProc(hWnd windows.HWND, msg uint32, wParam, lParam uintptr) (result uintptr) {
	switch msg {
	case _WM_CREATE:
		err := registerSessionNotification(_WTS_CURRENT_SERVER_HANDLE, hWnd, _NOTIFY_FOR_ALL_SESSIONS)
		if err != nil {
			sw.logf("[unexpected] failed to register for session notifications: %v", err)
			return ^uintptr(0)
		}
		sw.logf("registered for session notifications")
	case _WM_WTSSESSION_CHANGE:
		sw.handler(SessionID(lParam), uint32(wParam))
		return 0
	case _WM_CLOSE:
		if err := destroyWindow(hWnd); err != nil {
			sw.logf("[unexpected] failed to destroy window: %v", err)
		}
		return 0
	case _WM_DESTROY:
		err := unregisterSessionNotification(_WTS_CURRENT_SERVER_HANDLE, hWnd)
		if err != nil {
			sw.logf("[unexpected] failed to unregister session notifications callback: %v", err)
		}
		sw.logf("unregistered from session notifications")
		return 0
	case _WM_NCDESTROY:
		sw.hWnd = 0
		postQuitMessage(0) // quit the message loop for this thread
	}
	return defWindowProc(hWnd, msg, wParam, lParam)
}

func (sw *sessionWatcher) setHandle(hwnd windows.HWND) error {
	sw.hWnd = hwnd
	setLastError(0)
	_, err := setWindowLongPtr(sw.hWnd, _GWLP_USERDATA, uintptr(unsafe.Pointer(sw)))
	return err // may be nil or non-nil
}

func sessionWatcherByHandle(hwnd windows.HWND) *sessionWatcher {
	val, _ := getWindowLongPtr(hwnd, _GWLP_USERDATA)
	return (*sessionWatcher)(unsafe.Pointer(val))
}

func sessionWatcherWndProc(hWnd windows.HWND, msg uint32, wParam, lParam uintptr) (result uintptr) {
	if msg == _WM_NCCREATE {
		cs := (*_CREATESTRUCT)(unsafe.Pointer(lParam))
		sw := (*sessionWatcher)(unsafe.Pointer(cs.CreateParams))
		if sw == nil {
			return 0
		}
		if err := sw.setHandle(hWnd); err != nil {
			return 0
		}
		return defWindowProc(hWnd, msg, wParam, lParam)
	}
	if sw := sessionWatcherByHandle(hWnd); sw != nil {
		return sw.wndProc(hWnd, msg, wParam, lParam)
	}
	return defWindowProc(hWnd, msg, wParam, lParam)
}

func pumpThreadMessages() {
	var msg _MSG
	for getMessage(&msg, 0, 0, 0) != 0 {
		translateMessage(&msg)
		dispatchMessage(&msg)
	}
}

// waitUntilWTSReady waits until the Windows Terminal Services (WTS) is ready.
// This is necessary because the WTS API functions may fail if called before
// the WTS is ready.
//
// https://web.archive.org/web/20250207011738/https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotificationex
func waitUntilWTSReady(ctx context.Context) error {
	eventName16, err := windows.UTF16PtrFromString(`Global\TermSrvReadyEvent`)
	if err != nil {
		return err
	}
	event, err := windows.OpenEvent(windows.SYNCHRONIZE, false, eventName16)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	return waitForContextOrHandle(ctx, event)
}

// waitForContextOrHandle waits for either the context to be done or a handle to be signaled.
func waitForContextOrHandle(ctx context.Context, handle windows.Handle) error {
	contextDoneEvent, cleanup, err := channelToEvent(ctx.Done())
	if err != nil {
		return err
	}
	defer cleanup()

	handles := []windows.Handle{contextDoneEvent, handle}
	waitCode, err := windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
	if err != nil {
		return err
	}

	waitCode -= windows.WAIT_OBJECT_0
	if waitCode == 0 { // contextDoneEvent
		return ctx.Err()
	}
	return nil
}

// channelToEvent returns an auto-reset event that is set when the channel
// becomes receivable, including when the channel is closed.
func channelToEvent[T any](c <-chan T) (evt windows.Handle, cleanup func(), err error) {
	evt, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, nil, err
	}

	cancel := make(chan struct{})

	go func() {
		select {
		case <-cancel:
			return
		case <-c:
		}
		windows.SetEvent(evt)
	}()

	cleanup = func() {
		close(cancel)
		windows.CloseHandle(evt)
	}

	return evt, cleanup, nil
}

type _WNDCLASSEX struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type _CREATESTRUCT struct {
	CreateParams uintptr
	Instance     windows.Handle
	Menu         windows.Handle
	Parent       windows.HWND
	Cy           int32
	Cx           int32
	Y            int32
	X            int32
	Style        int32
	Name         *uint16
	ClassName    *uint16
	ExStyle      uint32
}

type _POINT struct {
	X, Y int32
}

type _MSG struct {
	HWnd    windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      _POINT
}

const (
	_WM_CREATE    = 1
	_WM_DESTROY   = 2
	_WM_CLOSE     = 16
	_WM_NCCREATE  = 129
	_WM_QUIT      = 18
	_WM_NCDESTROY = 130

	// _WM_WTSSESSION_CHANGE is a message sent to windows that have registered
	// for session change notifications, informing them of changes in session state.
	//
	// https://web.archive.org/web/20250207012421/https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change
	_WM_WTSSESSION_CHANGE = 0x02B1
)

const _GWLP_USERDATA = -21

const _HWND_MESSAGE = ^windows.HWND(2)

// _NOTIFY_FOR_ALL_SESSIONS indicates that the window should receive
// session change notifications for all sessions on the specified server.
const _NOTIFY_FOR_ALL_SESSIONS = 1

// _WTS_CURRENT_SERVER_HANDLE indicates that the window should receive
// session change notifications for the host itself rather than a remote server.
const _WTS_CURRENT_SERVER_HANDLE = windows.Handle(0)

// _WTS_CONNECTSTATE_CLASS represents the connection state of a session.
//
// https://web.archive.org/web/20250206082427/https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_connectstate_class
type _WTS_CONNECTSTATE_CLASS int32

// ToSessionStatus converts cs to a [SessionStatus].
func (cs _WTS_CONNECTSTATE_CLASS) ToSessionStatus() SessionStatus {
	switch cs {
	case windows.WTSActive:
		return ForegroundSession
	case windows.WTSDisconnected:
		return BackgroundSession
	default:
		// The session does not exist as far as we're concerned.
		return ClosedSession
	}
}

var (
	procGetWindowLongPtrW *windows.LazyProc
	procSetWindowLongPtrW *windows.LazyProc
)

func init() {
	// GetWindowLongPtrW and SetWindowLongPtrW are only available on 64-bit platforms.
	// https://web.archive.org/web/20250414195520/https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowlongptrw
	if runtime.GOARCH == "386" || runtime.GOARCH == "arm" {
		procGetWindowLongPtrW = moduser32.NewProc("GetWindowLongW")
		procSetWindowLongPtrW = moduser32.NewProc("SetWindowLongW")
	} else {
		procGetWindowLongPtrW = moduser32.NewProc("GetWindowLongPtrW")
		procSetWindowLongPtrW = moduser32.NewProc("SetWindowLongPtrW")
	}
}

func getWindowLongPtr(hwnd windows.HWND, index int32) (res uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procGetWindowLongPtrW.Addr(), 2, uintptr(hwnd), uintptr(index), 0)
	res = uintptr(r0)
	if res == 0 && e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func setWindowLongPtr(hwnd windows.HWND, index int32, newLong uintptr) (res uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procSetWindowLongPtrW.Addr(), 3, uintptr(hwnd), uintptr(index), uintptr(newLong))
	res = uintptr(r0)
	if res == 0 && e1 != 0 {
		err = errnoErr(e1)
	}
	return
}
