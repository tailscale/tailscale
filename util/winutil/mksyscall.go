// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

//sys getProcessMitigationPolicy(hProcess windows.Handle, mitigationPolicy _PROCESS_MITIGATION_POLICY, buf unsafe.Pointer, bufLen uintptr) (err error) [int32(failretval)==0] = kernel32.GetProcessMitigationPolicy
//sys queryServiceConfig2(hService windows.Handle, infoLevel uint32, buf *byte, bufLen uint32, bytesNeeded *uint32) (err error) [int32(failretval)==0] = advapi32.QueryServiceConfig2W
//sys registerApplicationRestart(cmdLineExclExeName *uint16, flags uint32) (ret wingoes.HRESULT) = kernel32.RegisterApplicationRestart
//sys setProcessMitigationPolicy(mitigationPolicy _PROCESS_MITIGATION_POLICY, buf unsafe.Pointer, bufLen uintptr) (err error) [int32(failretval)==0] = kernel32.SetProcessMitigationPolicy
