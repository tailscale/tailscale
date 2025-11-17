// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"unsafe"

	"github.com/dblohm7/wingoes"
	"golang.org/x/sys/windows"
)

var (
	// ErrAlreadyResolved is returned by (*StartupInfoBuilder).Resolve when the
	// StartupInfoBuilder has already been resolved.
	ErrAlreadyResolved = errors.New("StartupInfo already resolved")
	// ErrAlreadySet is returned by StartupInfoBuilder setters if the value
	// has already been set.
	ErrAlreadySet = errors.New("StartupInfoBuilder value already set")
	// ErrTooManyMitigationPolicyArguments is returned by
	// (*StartupInfoBuilder).AddMitigationPolicyFlags if more arguments are
	// passed than are supported by the current version of Windows. This error
	// may be wrapped with additional information, so use [errors.Is] to check for it.
	ErrTooManyMitigationPolicyArguments = errors.New("too many mitigation policy arguments for current Windows version")
)

// Attribute IDs not yet present in x/sys/windows
const (
	_PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
)

// Mitigation flags from the Win32 SDK
const (
	PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON      = (1 << 32)
	PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = (1 << 44)
	PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON         = (1 << 52)
	PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON      = (1 << 56)
	PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON   = (1 << 60)
)

// StartupInfoBuilder constructs a Windows STARTUPINFOEX and optional
// process/thread attribute list for use with the CreateProcess family of APIs.
type StartupInfoBuilder struct {
	siex          windows.StartupInfoEx
	attrs         map[uintptr]any // attr -> value
	attrContainer *windows.ProcThreadAttributeListContainer
}

func (sib *StartupInfoBuilder) Close() error {
	si := &sib.siex.StartupInfo
	if (si.Flags & windows.STARTF_USESTDHANDLES) != 0 {
		for _, h := range []windows.Handle{si.StdInput, si.StdOutput, si.StdErr} {
			if canBeInherited(h) {
				windows.CloseHandle(h)
			}
		}
	}

	sib.siex = windows.StartupInfoEx{}
	if sib.attrContainer != nil {
		sib.attrContainer.Delete()
		sib.attrContainer = nil
	}

	sib.attrs = nil
	return nil
}

// Resolve causes all settings and attributes stored within sib to be processed
// and formatted into valid arguments for use by CreateProcess* APIs.
// The returned values will not be altered any further by sib, so the caller
// is free to make additional customizations to the returned values prior to
// passing them into CreateProcess.
func (sib *StartupInfoBuilder) Resolve() (startupInfo *windows.StartupInfo, inheritHandles bool, createProcessFlags uint32, err error) {
	if sib.siex.StartupInfo.Cb != 0 {
		return nil, false, 0, ErrAlreadyResolved
	}

	// Always create a Unicode environment.
	createProcessFlags = windows.CREATE_UNICODE_ENVIRONMENT

	if ln := uint32(len(sib.attrs)); ln > 0 {
		attrCont, err := windows.NewProcThreadAttributeList(ln)
		if err != nil {
			return nil, false, 0, err
		}
		defer func() {
			if err != nil {
				attrCont.Delete()
			}
		}()

		for attr, val := range sib.attrs {
			var pval unsafe.Pointer
			var sval uintptr
			switch v := val.(type) {
			case windows.Handle:
				// An individual handle is pointer-width and is thus passed by value.
				pval = unsafe.Pointer(v)
				sval = unsafe.Sizeof(v)
			case []uint64:
				pval = unsafe.Pointer(unsafe.SliceData(v))
				sval = unsafe.Sizeof(v[0]) * uintptr(len(v))
			case []windows.Handle:
				pval = unsafe.Pointer(unsafe.SliceData(v))
				sval = unsafe.Sizeof(v[0]) * uintptr(len(v))
			default:
				panic("unsupported data type")
			}

			// Note that pointer keepalives are managed by attrCont.
			if err := attrCont.Update(attr, pval, sval); err != nil {
				return nil, false, 0, err
			}

			if attr == windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST {
				inheritHandles = true
			}
		}

		sib.attrContainer = attrCont
		sib.siex.ProcThreadAttributeList = attrCont.List()
		sib.siex.StartupInfo.Cb = uint32(unsafe.Sizeof(sib.siex))
		createProcessFlags |= windows.EXTENDED_STARTUPINFO_PRESENT
	} else {
		sib.siex.StartupInfo.Cb = uint32(unsafe.Sizeof(sib.siex.StartupInfo))
	}

	return &sib.siex.StartupInfo, inheritHandles, createProcessFlags, nil
}

func canBeInherited(h windows.Handle) bool {
	if h == 0 || h == windows.InvalidHandle {
		return false
	}

	ft, _ := windows.GetFileType(h)
	switch ft {
	case windows.FILE_TYPE_DISK, windows.FILE_TYPE_PIPE:
		return true
	case windows.FILE_TYPE_CHAR:
		// Console handles are treated differently from other character devices.
		// In particular, they should not be set up to be inherited like other
		// kernel handles. We determine whether h is a console handle by attempting
		// to retrieve its console mode. If this call fails then h is not a console.
		var mode uint32
		return windows.GetConsoleMode(h, &mode) != nil
	default:
		return false
	}
}

// SetStdHandles sets the StdInput, StdOutput, and StdErr handles and configures
// their inheritability as needed. When the handles are valid, non-console
// kernel objects, sib takes ownership of of them. All three handles may be set
// to zero to indicate that the parent's std handles should not be implicitly
// inherited.
//
// It returns ErrAlreadySet if the handles have already been set by a previous call.
func (sib *StartupInfoBuilder) SetStdHandles(stdin, stdout, stderr windows.Handle) error {
	if (sib.siex.StartupInfo.Flags & windows.STARTF_USESTDHANDLES) != 0 {
		return ErrAlreadySet
	}

	toInherit := make([]windows.Handle, 0, 3)
	for _, h := range []windows.Handle{stdin, stdout, stderr} {
		if !canBeInherited(h) {
			continue
		}

		toInherit = append(toInherit, h)
	}

	if err := sib.InheritHandles(toInherit...); err != nil {
		return err
	}

	sib.siex.StartupInfo.Flags |= windows.STARTF_USESTDHANDLES
	sib.siex.StartupInfo.StdInput = stdin
	sib.siex.StartupInfo.StdOutput = stdout
	sib.siex.StartupInfo.StdErr = stderr
	return nil
}

func (sib *StartupInfoBuilder) makeAttrs() {
	if sib.attrs == nil {
		// The size of this map should correspond to the number of distinct
		// attribute values supported by the StartupInfoBuilder API. Currently
		// we support four:
		// * Inheritable handle list;
		// * Pseudoconsole;
		// * Mitigation policy;
		// * Job list
		sib.attrs = make(map[uintptr]any, 4)
	}
}

func (sib *StartupInfoBuilder) getAttr(attr uintptr) any {
	sib.makeAttrs()
	return sib.attrs[attr]
}

// InheritHandles configures each handle in handles to be inheritable and adds
// it to the inheritable handle list proc/thread attribute. handles must consist
// entirely of kernel objects (handles that are closed via windows.CloseHandle).
// InheritHandles may be called multiple times; each successive call accumulates
// handles into an internal list maintained by sib.
func (sib *StartupInfoBuilder) InheritHandles(handles ...windows.Handle) error {
	if len(handles) == 0 {
		return nil
	}

	newHandles := make([]windows.Handle, 0, len(handles))
	for _, h := range handles {
		if h == 0 || h == windows.InvalidHandle || slices.Contains(newHandles, h) {
			continue
		}

		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return err
		}

		newHandles = append(newHandles, h)
	}

	if len(newHandles) == 0 {
		return nil
	}

	var handleList []windows.Handle
	if attrv := sib.getAttr(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST); attrv != nil {
		handleList = attrv.([]windows.Handle)
	}

	sib.attrs[windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST] = append(handleList, newHandles...)
	return nil
}

// AddMitigationPolicyFlags sets the process mitigation policy flags in newFlags
// on the mitigation policy proc/thread attribute. It accepts a different
// number of arguments depending on the current Windows version. If the
// current Windows version is Windows 10 build 1703 or newer, it accepts up to
// two arguments. It only accepts one argument on older versions of Windows 10.
// If too many arguments are supplied, AddMitigationPolicyFlags returns
// ErrTooManyMitigationPolicyArguments wrapped with additional information;
// use errors.Is to check for this error.
// AddMitigationPolicyFlags may be called multiple times; each successive call
// accumulates additional flags into the mitigation policy.
func (sib *StartupInfoBuilder) AddMitigationPolicyFlags(newFlags ...uint64) error {
	if len(newFlags) == 0 {
		return nil
	}

	supportedLen := 1
	if wingoes.IsWin10BuildOrGreater(wingoes.Win10Build1703) {
		supportedLen++
	}

	if len(newFlags) > supportedLen {
		return fmt.Errorf("%w: no more than %d allowed", ErrTooManyMitigationPolicyArguments, supportedLen)
	}

	attrv := sib.getAttr(windows.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)
	switch v := attrv.(type) {
	case nil:
		sib.attrs[windows.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY] = newFlags
	case []uint64:
		if newElems := len(newFlags) - len(v); newElems > 0 {
			v = append(v, make([]uint64, newElems)...)
			sib.attrs[windows.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY] = v
		}
		for i := range v {
			v[i] |= newFlags[i]
		}
	default:
		panic("unexpected attribute type")
	}

	return nil
}

// SetPseudoConsole sets pty as the pseudoconsole proc/thread attribute.
// pty must be a conpty handle. It returns ErrAlreadySet if the pty has already
// been successfully set by a previous call.
func (sib *StartupInfoBuilder) SetPseudoConsole(pty windows.Handle) error {
	if pty == 0 {
		return os.ErrInvalid
	}

	if attrv := sib.getAttr(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE); attrv != nil {
		return ErrAlreadySet
	}

	sib.attrs[windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE] = pty
	return nil
}

// AssignToJob assigns the process created by sib to job. AssignToJob may be
// called multiple times to assign the process to multiple jobs.
func (sib *StartupInfoBuilder) AssignToJob(job windows.Handle) error {
	if job == 0 {
		return os.ErrInvalid
	}

	var jobList []windows.Handle
	if attrv := sib.getAttr(_PROC_THREAD_ATTRIBUTE_JOB_LIST); attrv != nil {
		jobList = attrv.([]windows.Handle)
	}
	if slices.Contains(jobList, job) {
		return nil
	}

	sib.attrs[_PROC_THREAD_ATTRIBUTE_JOB_LIST] = append(jobList, job)
	return nil
}
