// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package desktop

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

//sys getTickCount64() (res uint64) = kernel32.GetTickCount64
//sys setLastError(dwErrorCode uint32) = kernel32.SetLastError
//sys switchToThread() (res bool) = kernel32.SwitchToThread

//sys registerClassEx(windowClass *_WNDCLASSEX) (atom uint16, err error) [atom==0] = user32.RegisterClassExW
//sys createWindowEx(dwExStyle uint32, lpClassName *uint16, lpWindowName *uint16, dwStyle uint32, x int32, y int32, nWidth int32, nHeight int32, hWndParent windows.HWND, hMenu windows.Handle, hInstance windows.Handle, lpParam unsafe.Pointer) (hWnd windows.HWND, err error) [hWnd==0] = user32.CreateWindowExW
//sys defWindowProc(hwnd windows.HWND, msg uint32, wparam uintptr, lparam uintptr) (res uintptr) = user32.DefWindowProcW
//sys setWindowLongPtr(hwnd windows.HWND, index int32, newLong uintptr) (res uintptr, err error) [res==0 && e1!=0] = user32.SetWindowLongPtrW
//sys getWindowLongPtr(hwnd windows.HWND, index int32) (res uintptr, err error) [res==0 && e1!=0] = user32.GetWindowLongPtrW
//sys sendMessage(hwnd windows.HWND, msg uint32, wparam uintptr, lparam uintptr) (res uintptr) = user32.SendMessageW
//sys getQueueStatus(flags uint32) (ret uint32) = user32.GetQueueStatus
//sys msgWaitForMultipleObjectsEx(count uint32, handles *windows.Handle, timeoutMillis uint32, wakeMask uint32, flags uint32) (ret uint32, err error) [failretval==windows.WAIT_FAILED] = user32.MsgWaitForMultipleObjectsEx
//sys peekMessage(lpMsg *_MSG, hwnd windows.HWND, msgMin uint32, msgMax uint32, remove uint32) (ret bool) = user32.PeekMessageW
//sys translateMessage(lpMsg *_MSG) (res bool) = user32.TranslateMessage
//sys dispatchMessage(lpMsg *_MSG) (res uintptr) = user32.DispatchMessageW
//sys destroyWindow(hwnd windows.HWND) (err error) [int32(failretval)==0] = user32.DestroyWindow
//sys postQuitMessage(exitCode int32) = user32.PostQuitMessage

//sys registerSessionNotification(hServer windows.Handle, hwnd windows.HWND, flags uint32) (err error) [int32(failretval)==0] = wtsapi32.WTSRegisterSessionNotificationEx
//sys unregisterSessionNotification(hServer windows.Handle, hwnd windows.HWND) (err error) [int32(failretval)==0] = wtsapi32.WTSUnRegisterSessionNotificationEx
