// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package desktop

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

//sys setLastError(dwErrorCode uint32) = kernel32.SetLastError

//sys registerClassEx(windowClass *_WNDCLASSEX) (atom uint16, err error) [atom==0] = user32.RegisterClassExW
//sys createWindowEx(dwExStyle uint32, lpClassName *uint16, lpWindowName *uint16, dwStyle uint32, x int32, y int32, nWidth int32, nHeight int32, hWndParent windows.HWND, hMenu windows.Handle, hInstance windows.Handle, lpParam unsafe.Pointer) (hWnd windows.HWND, err error) [hWnd==0] = user32.CreateWindowExW
//sys defWindowProc(hwnd windows.HWND, msg uint32, wparam uintptr, lparam uintptr) (res uintptr) = user32.DefWindowProcW
//sys sendMessage(hwnd windows.HWND, msg uint32, wparam uintptr, lparam uintptr) (res uintptr) = user32.SendMessageW
//sys getMessage(lpMsg *_MSG, hwnd windows.HWND, msgMin uint32, msgMax uint32) (ret int32) = user32.GetMessageW
//sys translateMessage(lpMsg *_MSG) (res bool) = user32.TranslateMessage
//sys dispatchMessage(lpMsg *_MSG) (res uintptr) = user32.DispatchMessageW
//sys destroyWindow(hwnd windows.HWND) (err error) [int32(failretval)==0] = user32.DestroyWindow
//sys postQuitMessage(exitCode int32) = user32.PostQuitMessage

//sys registerSessionNotification(hServer windows.Handle, hwnd windows.HWND, flags uint32) (err error) [int32(failretval)==0] = wtsapi32.WTSRegisterSessionNotificationEx
//sys unregisterSessionNotification(hServer windows.Handle, hwnd windows.HWND) (err error) [int32(failretval)==0] = wtsapi32.WTSUnRegisterSessionNotificationEx
