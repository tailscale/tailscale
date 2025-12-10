// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

type _MIB_IF_ENTRY_LEVEL int32

const (
	_MibIfEntryNormal                  _MIB_IF_ENTRY_LEVEL = 0
	_MibIfEntryNormalWithoutStatistics _MIB_IF_ENTRY_LEVEL = 2
)

//sys getIfEntry2(row *winipcfg.MibIfRow2) (ret error) = iphlpapi.GetIfEntry2
//sys getIfEntry2Ex(level _MIB_IF_ENTRY_LEVEL, row *winipcfg.MibIfRow2) (ret error) = iphlpapi.GetIfEntry2Ex
