// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osdiag

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

//sys globalMemoryStatusEx(memStatus *_MEMORYSTATUSEX) (err error) [int32(failretval)==0] = kernel32.GlobalMemoryStatusEx
//sys regEnumValue(key registry.Key, index uint32, valueName *uint16, valueNameLen *uint32, reserved *uint32, valueType *uint32, pData *byte, cbData *uint32) (ret error) [failretval!=0] = advapi32.RegEnumValueW
//sys wscEnumProtocols(iProtocols *int32, protocolBuffer *wsaProtocolInfo, bufLen *uint32, errno *int32) (ret int32) = ws2_32.WSCEnumProtocols
//sys wscGetProviderInfo(providerId *windows.GUID, infoType _WSC_PROVIDER_INFO_TYPE, info unsafe.Pointer, infoSize *uintptr, flags uint32, errno *int32) (ret int32) = ws2_32.WSCGetProviderInfo
//sys wscGetProviderPath(providerId *windows.GUID, providerDllPath *uint16, providerDllPathLen *int32, errno *int32) (ret int32) = ws2_32.WSCGetProviderPath
