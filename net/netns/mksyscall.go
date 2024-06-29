// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netns

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

//sys getBestInterfaceEx(sockaddr *winipcfg.RawSockaddrInet, bestIfaceIndex *uint32) (ret error) = iphlpapi.GetBestInterfaceEx
