// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package s4u

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

//sys allocateLocallyUniqueId(luid *windows.LUID) (err error) [int32(failretval)==0] = advapi32.AllocateLocallyUniqueId
//sys impersonateLoggedOnUser(token windows.Token) (err error) [int32(failretval)==0] = advapi32.ImpersonateLoggedOnUser
//sys lsaConnectUntrusted(lsaHandle *_LSAHANDLE) (ret windows.NTStatus) = secur32.LsaConnectUntrusted
//sys lsaDeregisterLogonProcess(lsaHandle _LSAHANDLE) (ret windows.NTStatus) = secur32.LsaDeregisterLogonProcess
//sys lsaFreeReturnBuffer(buffer uintptr) (ret windows.NTStatus) = secur32.LsaFreeReturnBuffer
//sys lsaLogonUser(lsaHandle _LSAHANDLE, originName *windows.NTString, logonType _SECURITY_LOGON_TYPE, authenticationPackage uint32, authenticationInformation unsafe.Pointer, authenticationInformationLength uint32, localGroups *windows.Tokengroups, sourceContext *_TOKEN_SOURCE, profileBuffer *uintptr, profileBufferLength *uint32, logonID *windows.LUID, token *windows.Token, quotas *_QUOTA_LIMITS, subStatus *windows.NTStatus) (ret windows.NTStatus) = secur32.LsaLogonUser
//sys lsaLookupAuthenticationPackage(lsaHandle _LSAHANDLE, packageName *windows.NTString, authenticationPackage *uint32) (ret windows.NTStatus) = secur32.LsaLookupAuthenticationPackage
//sys lsaRegisterLogonProcess(logonProcessName *windows.NTString, lsaHandle *_LSAHANDLE, securityMode *_LSA_OPERATIONAL_MODE) (ret windows.NTStatus) = secur32.LsaRegisterLogonProcess
