// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

//sys queryServiceConfig2(hService windows.Handle, infoLevel uint32, buf *byte, bufLen uint32, bytesNeeded *uint32) (err error) [failretval==0] = advapi32.QueryServiceConfig2W
//sys regEnumValue(key registry.Key, index uint32, valueName *uint16, valueNameLen *uint32, reserved *uint32, valueType *uint32, pData *byte, cbData *uint32) (ret error) [failretval!=0] = advapi32.RegEnumValueW
