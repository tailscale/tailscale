// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vss provides a minimal set of wrappers for the COM interfaces used for
// accessing Windows's Volume Shadow Copy Service.
package vss

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Type representing a C pointer to a null-terminated UTF-16 string that was allocated
// by the COM runtime.
type COMAllocatedString uintptr
type VSS_TIMESTAMP int64

// SnapshotProperties is the Go representation of the VSS_SNAPSHOT_PROP structure from the Windows SDK
type SnapshotProperties struct {
	SnapshotId           windows.GUID
	SnapshotSetId        windows.GUID
	SnapshotsCount       int32
	SnapshotDeviceObject COMAllocatedString
	OriginalVolumeName   COMAllocatedString
	OriginatingMachine   COMAllocatedString
	ServiceMachine       COMAllocatedString
	ExposedName          COMAllocatedString
	ExposedPath          COMAllocatedString
	ProviderId           windows.GUID
	SnapshotAttributes   int32
	CreationTimestamp    VSS_TIMESTAMP
	Status               int32
}

// Because of the constraints that this package applies to queries, the objType
// field may be ignored when reading its data.
type ObjectProperties struct {
	objType int32
	Obj     SnapshotProperties
}

type SnapshotList []ObjectProperties

// SnapshotEnumerator is the interface that enables execution of a VSS query.
// QuerySnapshots returns a SnapshotList of all available snapshots.
// The elements of the SnapshotList should be returned in reverse chronological order.
type SnapshotEnumerator interface {
	io.Closer
	QuerySnapshots() (SnapshotList, error)
}

var (
	vssApi                                = windows.NewLazySystemDLL("VssApi.dll")
	procCreateVssBackupComponentsInternal = vssApi.NewProc("CreateVssBackupComponentsInternal")
)

const vssCtxClientAccessibleWriters = 0x0000000d

// NewSnapshotEnumerator instantiates the necessary OS facilities for accessing
// the Volume Shadow Copy service, and then returns a SnapshotEnumerator that
// may then be used for executing a query against the service.
func NewSnapshotEnumerator() (SnapshotEnumerator, error) {
	var result vssBackupComponentsWrap
	hresult, _, _ := procCreateVssBackupComponentsInternal.Call(uintptr(unsafe.Pointer(&result.iface)))
	err := errorFromHRESULT(hresult)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			result.Close()
		}
	}()

	err = result.iface.InitializeForBackup()
	if err != nil {
		return nil, err
	}

	// vssCtxClientAccessibleWriters is the context that we need to be able to access
	// system restore points.
	err = result.iface.SetContext(vssCtxClientAccessibleWriters)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *COMAllocatedString) Close() error {
	if s != nil {
		windows.CoTaskMemFree(unsafe.Pointer(*s))
		*s = 0
	}

	return nil
}

func (s *COMAllocatedString) String() string {
	if s == nil {
		return "<nil>"
	}

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(*s)))
}

func (ts VSS_TIMESTAMP) ToFiletime() windows.Filetime {
	return *((*windows.Filetime)(unsafe.Pointer(&ts)))
}

// Converts a windows.Filetime to a VSS_TIMESTAMP
func VSSTimestampFromFiletime(ft windows.Filetime) VSS_TIMESTAMP {
	return *((*VSS_TIMESTAMP)(unsafe.Pointer(&ft)))
}

func (p *SnapshotProperties) Close() error {
	if p == nil {
		return nil
	}

	p.SnapshotDeviceObject.Close()
	p.OriginalVolumeName.Close()
	p.OriginatingMachine.Close()
	p.ServiceMachine.Close()
	p.ExposedName.Close()
	p.ExposedPath.Close()
	return nil
}

func (props *ObjectProperties) Close() error {
	if props == nil {
		return nil
	}

	return props.Obj.Close()
}

func (snapList *SnapshotList) Close() error {
	if snapList == nil {
		return nil
	}

	for _, snap := range *snapList {
		snap.Close()
	}

	return nil
}

func errorFromHRESULT(value uintptr) error {
	// In C, HRESULTS are typedef'd as LONG, which on Windows is always int32
	hr := int32(value)
	if hr < 0 {
		return windows.Errno(hr)
	}

	return nil
}

type unknownVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
}

// The complete vtable for IVssEnumObject.
// We only call Release and Next, so most of these fields, while populated by
// Windows, are unused by us.
type vssEnumObjectVtbl struct {
	unknownVtbl
	Next  uintptr
	Skip  uintptr
	Reset uintptr
	Clone uintptr
}

type vssEnumObjectABI struct {
	vtbl *vssEnumObjectVtbl
}

func (iface *vssEnumObjectABI) Release() int32 {
	result, _, _ := syscall.Syscall(iface.vtbl.Release, 1, uintptr(unsafe.Pointer(iface)), 0, 0)
	return int32(result)
}

func (iface *vssEnumObjectABI) Next() ([]ObjectProperties, error) {
	var props [16]ObjectProperties
	var numFetched uint32
	hresult, _, _ := syscall.Syscall6(iface.vtbl.Next, 4, uintptr(unsafe.Pointer(iface)),
		uintptr(len(props)), uintptr(unsafe.Pointer(&props[0])), uintptr(unsafe.Pointer(&numFetched)), 0, 0)

	err := errorFromHRESULT(hresult)
	if err != nil {
		return nil, err
	}

	// For some reason x/sys/windows gives HRESULT error codes a type of
	// windows.Handle, which is wrong, so we're being explicit here.
	if int32(hresult) == int32(windows.S_FALSE) {
		err = io.EOF
	}

	return props[:numFetched], err
}

// The complete vtable for IVssBackupComponents.
// We only call Release, InitializeForBackup, SetContext, and Query,
// so most of these fields, while populated by Windows, are unused by us.
type vssBackupComponentsVtbl struct {
	unknownVtbl
	GetWriterComponentsCount      uintptr
	GetWriterComponents           uintptr
	InitializeForBackup           uintptr
	SetBackupState                uintptr
	InitializeForRestore          uintptr
	SetRestoreState               uintptr
	GatherWriterMetadata          uintptr
	GetWriterMetadataCount        uintptr
	GetWriterMetadata             uintptr
	FreeWriterMetadata            uintptr
	AddComponent                  uintptr
	PrepareForBackup              uintptr
	AbortBackup                   uintptr
	GatherWriterStatus            uintptr
	GetWriterStatusCount          uintptr
	FreeWriterStatus              uintptr
	GetWriterStatus               uintptr
	SetBackupSucceeded            uintptr
	SetBackupOptions              uintptr
	SetSelectedForRestore         uintptr
	SetRestoreOptions             uintptr
	SetAdditionalRestores         uintptr
	SetPreviousBackupStamp        uintptr
	SaveAsXML                     uintptr
	BackupComplete                uintptr
	AddAlternativeLocationMapping uintptr
	AddRestoreSubcomponent        uintptr
	SetFileRestoreStatus          uintptr
	AddNewTarget                  uintptr
	SetRangesFilePath             uintptr
	PreRestore                    uintptr
	PostRestore                   uintptr
	SetContext                    uintptr
	StartSnapshotSet              uintptr
	AddToSnapshotSet              uintptr
	DoSnapshotSet                 uintptr
	DeleteSnapshots               uintptr
	ImportSnapshots               uintptr
	BreakSnapshotSet              uintptr
	GetSnapshotProperties         uintptr
	Query                         uintptr
	IsVolumeSupported             uintptr
	DisableWriterClasses          uintptr
	EnableWriterClasses           uintptr
	DisableWriterInstances        uintptr
	ExposeSnapshot                uintptr
	RevertToSnapshot              uintptr
	QueryRevertStatus             uintptr
}

type vssBackupComponentsABI struct {
	vtbl *vssBackupComponentsVtbl
}

func (iface *vssBackupComponentsABI) Release() int32 {
	result, _, _ := syscall.Syscall(iface.vtbl.Release, 1, uintptr(unsafe.Pointer(iface)), 0, 0)
	return int32(result)
}

func (iface *vssBackupComponentsABI) InitializeForBackup() error {
	// Note that we pass a second argument that is a null C pointer, i.e. 0
	hresult, _, _ := syscall.Syscall(iface.vtbl.InitializeForBackup, 2, uintptr(unsafe.Pointer(iface)), 0, 0)
	return errorFromHRESULT(hresult)
}

func (iface *vssBackupComponentsABI) SetContext(context int32) error {
	hresult, _, _ := syscall.Syscall(iface.vtbl.SetContext, 2, uintptr(unsafe.Pointer(iface)), uintptr(context), 0)
	return errorFromHRESULT(hresult)
}

const (
	vssObjectUnknown     = 0
	vssObjectNone        = 1
	vssObjectSnapshotSet = 2
	vssObjectSnapshot    = 3
	vssObjectProvider    = 4
)

// QuerySnapshots returns the list of applicable snapshots as a SnapshotList
// (as opposed to a channel-based implementation) because we need to be able to
// access the snapshot information in reverse-chronological order.
func (iface *vssBackupComponentsABI) QuerySnapshots() (SnapshotList, error) {
	// Perform the Query. If successful, the query will produce an enumeration object.
	var GUID_NULL windows.GUID
	var enumObj *vssEnumObjectABI
	hresult, _, _ := syscall.Syscall6(iface.vtbl.Query, 5, uintptr(unsafe.Pointer(iface)), uintptr(unsafe.Pointer(&GUID_NULL)),
		vssObjectNone, vssObjectSnapshot, uintptr(unsafe.Pointer(&enumObj)), 0)
	err := errorFromHRESULT(hresult)
	if err != nil {
		return nil, err
	}
	defer enumObj.Release()

	// Build up the complete list of snapshots from the enumerator object.
	var result SnapshotList
	chunk, err := enumObj.Next()
	for ok := err == nil || errors.Is(err, io.EOF); ok; ok = err == nil {
		if result == nil {
			result = chunk
		} else {
			for _, item := range chunk {
				result = append(result, item)
			}
		}

		chunk, err = enumObj.Next()
	}

	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// Sort in reverse chronological order so we may easily iterate from newest to oldest
	sort.Slice(result, func(i, j int) bool {
		return result[i].Obj.CreationTimestamp > result[j].Obj.CreationTimestamp
	})

	return result, nil
}

type vssBackupComponentsWrap struct {
	iface *vssBackupComponentsABI
}

func (vss *vssBackupComponentsWrap) Close() error {
	if vss == nil || vss.iface == nil {
		return nil
	}

	vss.iface.Release()
	vss.iface = nil
	return nil
}

func (vss *vssBackupComponentsWrap) QuerySnapshots() (SnapshotList, error) {
	if vss == nil {
		return nil, fmt.Errorf("Called QuerySnapshots on a nil vssBackupComponentsWrap")
	}

	return vss.iface.QuerySnapshots()
}
