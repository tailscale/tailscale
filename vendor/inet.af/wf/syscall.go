// Copyright (c) 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wf

//sys fwpmEngineOpen0(mustBeNil *uint16, authnService authnService, authIdentity *uintptr, session *fwpmSession0, engineHandle *windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmEngineOpen0
//sys fwpmEngineClose0(engineHandle windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmEngineClose0

//sys fwpmLayerCreateEnumHandle0(engineHandle windows.Handle, enumTemplate *fwpmLayerEnumTemplate0, handle *windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmLayerCreateEnumHandle0
//sys fwpmLayerDestroyEnumHandle0(engineHandle windows.Handle, enumHandle windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmLayerDestroyEnumHandle0
//sys fwpmLayerEnum0(engineHandle windows.Handle, enumHandle windows.Handle, numEntriesRequested uint32, entries ***fwpmLayer0, numEntriesReturned *uint32) (ret error) [failretval!=0] = fwpuclnt.FwpmLayerEnum0

//sys fwpmSubLayerCreateEnumHandle0(engineHandle windows.Handle, enumTemplate *fwpmSublayerEnumTemplate0, handle *windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmSubLayerCreateEnumHandle0
//sys fwpmSubLayerDestroyEnumHandle0(engineHandle windows.Handle, enumHandle windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmSubLayerDestroyEnumHandle0
//sys fwpmSubLayerEnum0(engineHandle windows.Handle, enumHandle windows.Handle, numEntriesRequested uint32, entries ***fwpmSublayer0, numEntriesReturned *uint32) (ret error) [failretval!=0] = fwpuclnt.FwpmSubLayerEnum0
//sys fwpmSubLayerAdd0(engineHandle windows.Handle, sublayer *fwpmSublayer0, nilForNow *uintptr) (ret error) [failretval!=0] = fwpuclnt.FwpmSubLayerAdd0
//sys fwpmSubLayerDeleteByKey0(engineHandle windows.Handle, guid *SublayerID) (ret error) [failretval!=0] = fwpuclnt.FwpmSubLayerDeleteByKey0

//sys fwpmProviderCreateEnumHandle0(engineHandle windows.Handle, enumTemplate *struct{}, handle *windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmProviderCreateEnumHandle0
//sys fwpmProviderDestroyEnumHandle0(engineHandle windows.Handle, enumHandle windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmProviderDestroyEnumHandle0
//sys fwpmProviderEnum0(engineHandle windows.Handle, enumHandle windows.Handle, numEntriesRequested uint32, entries ***fwpmProvider0, numEntriesReturned *uint32) (ret error) [failretval!=0] = fwpuclnt.FwpmProviderEnum0
//sys fwpmProviderAdd0(engineHandle windows.Handle, provider *fwpmProvider0, nilForNow *uintptr) (ret error) [failretval!=0] = fwpuclnt.FwpmProviderAdd0
//sys fwpmProviderDeleteByKey0(engineHandle windows.Handle, guid *ProviderID) (ret error) [failretval!=0] = fwpuclnt.FwpmProviderDeleteByKey0

//sys fwpmFilterCreateEnumHandle0(engineHandle windows.Handle, enumTemplate *fwpmFilterEnumTemplate0, handle *windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmFilterCreateEnumHandle0
//sys fwpmFilterDestroyEnumHandle0(engineHandle windows.Handle, enumHandle windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmFilterDestroyEnumHandle0
//sys fwpmFilterEnum0(engineHandle windows.Handle, enumHandle windows.Handle, numEntriesRequested uint32, entries ***fwpmFilter0, numEntriesReturned *uint32) (ret error) [failretval!=0] = fwpuclnt.FwpmFilterEnum0
//sys fwpmFilterAdd0(engineHandle windows.Handle, rule *fwpmFilter0, sd *windows.SECURITY_DESCRIPTOR, id *uint64) (ret error) [failretval!=0] = fwpuclnt.FwpmFilterAdd0
//sys fwpmFilterDeleteByKey0(engineHandle windows.Handle, guid *RuleID) (ret error) [failretval!=0] = fwpuclnt.FwpmFilterDeleteByKey0

//sys fwpmNetEventCreateEnumHandle0(engineHandle windows.Handle, enumTemplate *struct{}, handle *windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmNetEventCreateEnumHandle0
//sys fwpmNetEventDestroyEnumHandle0(engineHandle windows.Handle, enumHandle windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmNetEventDestroyEnumHandle0
//sys fwpmNetEventEnum1(engineHandle windows.Handle, enumHandle windows.Handle, numEntriesRequested uint32, entries ***fwpmNetEvent1, numEntriesReturned *uint32) (ret error) [failretval!=0] = fwpuclnt.FwpmNetEventEnum1

//sys fwpmTransactionBegin0(engineHandle windows.Handle, flags uint32) (ret error) [failretval!=0] = fwpuclnt.FwpmTransactionBegin0
//sys fwpmTransactionCommit0(engineHandle windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmTransactionCommit0
//sys fwpmTransactionAbort0(engineHandle windows.Handle) (ret error) [failretval!=0] = fwpuclnt.FwpmTransactionAbort0

//sys fwpmFreeMemory0(p *struct{}) = fwpuclnt.FwpmFreeMemory0
//sys fwpmGetAppIdFromFileName0(path *byte, appId **fwpByteBlob) (ret error) [failretval!=0] = fwpuclnt.FwpmGetAppIdFromFileName0
