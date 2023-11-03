// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

//sys getApplicationRestartSettings(process windows.Handle, commandLine *uint16, commandLineLen *uint32, flags *uint32) (ret wingoes.HRESULT) = kernel32.GetApplicationRestartSettings
//sys queryServiceConfig2(hService windows.Handle, infoLevel uint32, buf *byte, bufLen uint32, bytesNeeded *uint32) (err error) [failretval==0] = advapi32.QueryServiceConfig2W
//sys registerApplicationRestart(cmdLineExclExeName *uint16, flags uint32) (ret wingoes.HRESULT) = kernel32.RegisterApplicationRestart
//sys rmEndSession(session _RMHANDLE) (ret error) = rstrtmgr.RmEndSession
//sys rmGetList(session _RMHANDLE, nProcInfoNeeded *uint32, nProcInfo *uint32, rgAffectedApps *_RM_PROCESS_INFO, pRebootReasons *uint32) (ret error) = rstrtmgr.RmGetList
//sys rmJoinSession(pSession *_RMHANDLE, sessionKey *uint16) (ret error) = rstrtmgr.RmJoinSession
//sys rmRegisterResources(session _RMHANDLE, nFiles uint32, rgsFileNames **uint16, nApplications uint32, rgApplications *_RM_UNIQUE_PROCESS, nServices uint32, rgsServiceNames **uint16) (ret error) = rstrtmgr.RmRegisterResources
//sys rmStartSession(pSession *_RMHANDLE, flags uint32, sessionKey *uint16) (ret error) = rstrtmgr.RmStartSession
