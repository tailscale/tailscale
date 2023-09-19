// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// StartProcessAsChild starts exePath process as a child of parentPID.
// StartProcessAsChild copies parentPID's environment variables into
// the new process, along with any optional environment variables in extraEnv.
func StartProcessAsChild(parentPID uint32, exePath string, extraEnv []string) error {
	return StartProcessWithAttributes(exePath, ProcessAttributeEnvExtra{Slice: extraEnv}, ProcessAttributeParentProcessID(parentPID))
}

func StartProcessWithAttributes(exePath string, attrs ...any) (err error) {
	var desktop string
	var parentPID uint32
	var mitigationBits uint64
	var inheritableHandleList ProcessAttributeExplicitInheritableHandleList
	var useStdHandles bool
	var useToken windows.Token
	var wd string
	var procSA *windows.SecurityAttributes
	var threadSA *windows.SecurityAttributes
	var envExtra ProcessAttributeEnvExtra
	var args []string
	creationFlags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)

	for _, attr := range attrs {
		switch v := attr.(type) {
		case ProcessAttributeExplicitInheritableHandleList:
			inheritableHandleList, useStdHandles, err = v.filtered()
			if err != nil {
				return err
			}
		case *ProcessAttributeExplicitInheritableHandleList:
			inheritableHandleList, useStdHandles, err = v.filtered()
			if err != nil {
				return err
			}
		case ProcessAttributeParentProcessID:
			parentPID = uint32(v)
		case *ProcessAttributeParentProcessID:
			parentPID = uint32(*v)
		case ProcessMitigationPolicies:
			mitigationBits = v.asMitigationBits()
		case *ProcessMitigationPolicies:
			mitigationBits = v.asMitigationBits()
		case windows.Token:
			useToken = v
		case ProcessAttributeGUIBindInfo:
			desktop = v.String()
		case *ProcessAttributeGUIBindInfo:
			desktop = v.String()
		case ProcessAttributeWorkingDirectory:
			wd = v.String()
		case *ProcessAttributeWorkingDirectory:
			wd = v.String()
		case ProcessAttributeSecurity:
			procSA = v.Process
			threadSA = v.Thread
		case *ProcessAttributeSecurity:
			procSA = v.Process
			threadSA = v.Thread
		case ProcessAttributeEnvExtra:
			envExtra = v
		case *ProcessAttributeEnvExtra:
			envExtra = *v
		case ProcessAttributeArgs:
			args = []string(v)
		case *ProcessAttributeArgs:
			args = []string(*v)
		case ProcessAttributeFlags:
			creationFlags |= v.creationFlags()
		case *ProcessAttributeFlags:
			creationFlags |= v.creationFlags()
		default:
			return os.ErrInvalid
		}
	}

	var attrCount uint32
	if len(inheritableHandleList.Handles) > 0 {
		attrCount++
	}
	if parentPID != 0 {
		attrCount++
	}
	if mitigationBits != 0 {
		attrCount++
	}

	var ph windows.Handle
	var env []string
	if parentPID == 0 {
		env = os.Environ()
	} else {
		// According to https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
		//
		// ... To open a handle to another process and obtain full access rights,
		// you must enable the SeDebugPrivilege privilege. ...
		//
		// But we only need PROCESS_CREATE_PROCESS. So perhaps SeDebugPrivilege is too much.
		//
		// https://devblogs.microsoft.com/oldnewthing/20080314-00/?p=23113
		//
		// TODO: try look for something less than SeDebugPrivilege

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err := windows.ImpersonateSelf(windows.SecurityImpersonation)
		if err != nil {
			return err
		}
		defer windows.RevertToSelf()

		err = EnableCurrentThreadPrivilege("SeDebugPrivilege")
		if err != nil {
			return err
		}

		ph, err = windows.OpenProcess(
			windows.PROCESS_CREATE_PROCESS|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_DUP_HANDLE,
			false, parentPID)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(ph)

		var pt windows.Token
		if err := windows.OpenProcessToken(ph, windows.TOKEN_QUERY, &pt); err != nil {
			return err
		}
		defer pt.Close()

		env, err = pt.Environ(false)
		if err != nil {
			return err
		}
	}

	env16 := envExtra.envBlock(env)

	var inheritHandles bool
	var attrList *windows.ProcThreadAttributeList
	if attrCount > 0 {
		attrListContainer, err := windows.NewProcThreadAttributeList(attrCount)
		if err != nil {
			return err
		}
		defer attrListContainer.Delete()

		if ph != 0 {
			attrListContainer.Update(windows.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, unsafe.Pointer(&ph), unsafe.Sizeof(ph))
		}

		if hll := uintptr(len(inheritableHandleList.Handles)); hll > 0 {
			attrListContainer.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inheritableHandleList.Handles[0]), hll*unsafe.Sizeof(windows.Handle(0)))
			inheritHandles = true
		}

		if mitigationBits != 0 {
			attrListContainer.Update(windows.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, unsafe.Pointer(&mitigationBits), unsafe.Sizeof(mitigationBits))
		}

		attrList = attrListContainer.List()
	}

	var desktop16 *uint16
	if desktop != "" {
		desktop16, err = windows.UTF16PtrFromString(desktop)
		if err != nil {
			return err
		}
	}

	var startupInfoFlags uint32
	if useStdHandles {
		startupInfoFlags |= windows.STARTF_USESTDHANDLES
	}

	siex := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Desktop:   desktop16,
			Flags:     startupInfoFlags,
			StdInput:  inheritableHandleList.Stdin,
			StdOutput: inheritableHandleList.Stdout,
			StdErr:    inheritableHandleList.Stderr,
		},
		ProcThreadAttributeList: attrList,
	}

	var wd16 *uint16
	if wd != "" {
		wd16, err = windows.UTF16PtrFromString(wd)
		if err != nil {
			return err
		}
	}

	exePath16, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return err
	}

	cmdLine, err := makeCmdLine(exePath, args)
	if err != nil {
		return err
	}

	var pi windows.ProcessInformation
	if useToken == 0 {
		err = windows.CreateProcess(exePath16, cmdLine, procSA, threadSA, inheritHandles, creationFlags, env16, wd16, &siex.StartupInfo, &pi)
	} else {
		err = windows.CreateProcessAsUser(useToken, exePath16, cmdLine, procSA, threadSA, inheritHandles, creationFlags, env16, wd16, &siex.StartupInfo, &pi)
	}

	runtime.KeepAlive(siex)

	if err != nil {
		return err
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	return err
}

func makeCmdLine(exePath string, args []string) (*uint16, error) {
	var buf strings.Builder

	buf.WriteString(windows.EscapeArg(exePath))

	for _, arg := range args {
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(windows.EscapeArg(arg))
	}

	return windows.UTF16PtrFromString(buf.String())
}

// StartProcessAsCurrentGUIUser is like StartProcessAsChild, but if finds
// current logged in user desktop process (normally explorer.exe),
// and passes found PID to StartProcessAsChild.
func StartProcessAsCurrentGUIUser(exePath string, extraEnv []string) error {
	// as described in https://devblogs.microsoft.com/oldnewthing/20190425-00/?p=102443
	desktop, err := GetDesktopPID()
	if err != nil {
		return fmt.Errorf("failed to find desktop: %v", err)
	}
	err = StartProcessAsChild(desktop, exePath, extraEnv)
	if err != nil {
		return fmt.Errorf("failed to start executable: %v", err)
	}
	return nil
}

type ProcessAttributeEnvExtra struct {
	Map   map[string]string
	Slice []string
}

func (ee *ProcessAttributeEnvExtra) envBlock(env []string) *uint16 {
	var buf bytes.Buffer

	for _, s := range [][]string{env, ee.Slice} {
		for _, v := range s {
			buf.WriteString(v)
			buf.WriteByte(0)
		}
	}

	for k, v := range ee.Map {
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(v)
		buf.WriteByte(0)
	}

	if buf.Len() == 0 {
		// So that we end with a double-null in the empty env case (unlikely)
		buf.WriteByte(0)
	}

	buf.WriteByte(0)

	return &utf16.Encode([]rune(string(buf.Bytes())))[0]
}

type ProcessAttributeFlags struct {
	BreakawayFromJob      bool
	CreateNewConsole      bool
	CreateNewProcessGroup bool
	Detached              bool
	InheritParentAffinity bool
	NoConsoleWindow       bool
}

func (paf *ProcessAttributeFlags) creationFlags() (result uint32) {
	if paf.BreakawayFromJob {
		result |= windows.CREATE_BREAKAWAY_FROM_JOB
	}
	if paf.CreateNewConsole {
		result |= windows.CREATE_NEW_CONSOLE
	}
	if paf.CreateNewProcessGroup {
		result |= windows.CREATE_NEW_PROCESS_GROUP
	}
	if paf.Detached {
		result |= windows.DETACHED_PROCESS
	}
	if paf.InheritParentAffinity {
		result |= windows.INHERIT_PARENT_AFFINITY
	}
	if paf.NoConsoleWindow {
		result |= windows.CREATE_NO_WINDOW
	}

	return result
}

type ProcessAttributeArgs []string

type ProcessAttributeSecurity struct {
	Process *windows.SecurityAttributes
	Thread  *windows.SecurityAttributes
}

type ProcessAttributeWorkingDirectory string

func (wd *ProcessAttributeWorkingDirectory) String() string {
	return string(*wd)
}

type ProcessAttributeGUIBindInfo struct {
	WindowStation string
	Desktop       string
}

func (gbi *ProcessAttributeGUIBindInfo) String() string {
	winsta := gbi.WindowStation
	if winsta == "" {
		winsta = "Winsta0"
	}

	desktop := gbi.Desktop
	if desktop == "" {
		desktop = "default"
	}

	var buf strings.Builder
	buf.WriteString(winsta)
	buf.WriteByte('\\')
	buf.WriteString(desktop)
	return buf.String()
}

type ProcessAttributeParentProcessID uint32

type ProcessAttributeExplicitInheritableHandleList struct {
	Stdin   windows.Handle
	Stdout  windows.Handle
	Stderr  windows.Handle
	Handles []windows.Handle
}

func (eihl *ProcessAttributeExplicitInheritableHandleList) filtered() (result ProcessAttributeExplicitInheritableHandleList, containsStd bool, err error) {
	result = ProcessAttributeExplicitInheritableHandleList{
		Stdin:   eihl.Stdin,
		Stdout:  eihl.Stdout,
		Stderr:  eihl.Stderr,
		Handles: make([]windows.Handle, 0, len(eihl.Handles)+3),
	}

	handles := make([]windows.Handle, 0, len(eihl.Handles)+3)

	if result.Stdin == 0 {
		result.Stdin = windows.Stdin
	}
	handles = append(handles, result.Stdin)

	if result.Stdout == 0 {
		result.Stdout = windows.Stdout
	}
	handles = append(handles, result.Stdout)

	if result.Stderr == 0 {
		result.Stderr = windows.Stderr
	}
	handles = append(handles, result.Stderr)

	handles = append(handles, eihl.Handles...)

	for i, h := range handles {
		fileType, err := windows.GetFileType(h)
		if err != nil {
			return result, false, err
		}
		if fileType != windows.FILE_TYPE_DISK && fileType != windows.FILE_TYPE_PIPE {
			continue
		}

		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return result, false, err
		}

		result.Handles = append(result.Handles, h)
		if i < 3 {
			// Standard handle
			containsStd = true
		}
	}

	return result, containsStd, nil
}

type _PROCESS_MITIGATION_POLICY int32

const (
	processDEPPolicy                   _PROCESS_MITIGATION_POLICY = 0
	processASLRPolicy                  _PROCESS_MITIGATION_POLICY = 1
	processDynamicCodePolicy           _PROCESS_MITIGATION_POLICY = 2
	processStrictHandleCheckPolicy     _PROCESS_MITIGATION_POLICY = 3
	processSystemCallDisablePolicy     _PROCESS_MITIGATION_POLICY = 4
	processMitigationOptionsMask       _PROCESS_MITIGATION_POLICY = 5
	processExtensionPointDisablePolicy _PROCESS_MITIGATION_POLICY = 6
	processControlFlowGuardPolicy      _PROCESS_MITIGATION_POLICY = 7
	processSignaturePolicy             _PROCESS_MITIGATION_POLICY = 8
	processFontDisablePolicy           _PROCESS_MITIGATION_POLICY = 9
	processImageLoadPolicy             _PROCESS_MITIGATION_POLICY = 10
	processSystemCallFilterPolicy      _PROCESS_MITIGATION_POLICY = 11
	processPayloadRestrictionPolicy    _PROCESS_MITIGATION_POLICY = 12
	processChildProcessPolicy          _PROCESS_MITIGATION_POLICY = 13
	processSideChannelIsolationPolicy  _PROCESS_MITIGATION_POLICY = 14
	processUserShadowStackPolicy       _PROCESS_MITIGATION_POLICY = 15
	processRedirectionTrustPolicy      _PROCESS_MITIGATION_POLICY = 16
	processUserPointerAuthPolicy       _PROCESS_MITIGATION_POLICY = 17
	processSEHOPPolicy                 _PROCESS_MITIGATION_POLICY = 18
)

type processMitigationPolicyFlags struct {
	Flags uint32
}

const (
	_NoRemoteImages            = 1
	_NoLowMandatoryLabelImages = (1 << 1)
	_PreferSystem32Images      = (1 << 2)
	_MicrosoftSignedOnly       = 1
	_DisableExtensionPoints    = 1
	_ProhibitDynamicCode       = 1
)

type ProcessMitigationPolicies struct {
	DisableExtensionPoints          bool
	PreferSystem32Images            bool
	ProhibitDynamicCode             bool
	ProhibitLowMandatoryLabelImages bool
	ProhibitNonMicrosoftSignedDLLs  bool
	ProhibitRemoteImages            bool
}

func CurrentProcessMitigationPolicies() (result ProcessMitigationPolicies, _ error) {
	var flags processMitigationPolicyFlags
	cp := windows.CurrentProcess()

	if err := getProcessMitigationPolicy(cp, processExtensionPointDisablePolicy, unsafe.Pointer(&flags), unsafe.Sizeof(flags)); err != nil {
		return result, err
	}
	result.DisableExtensionPoints = flags.Flags&_DisableExtensionPoints != 0

	if err := getProcessMitigationPolicy(cp, processSystemCallDisablePolicy, unsafe.Pointer(&flags), unsafe.Sizeof(flags)); err != nil {
		return result, err
	}
	result.ProhibitNonMicrosoftSignedDLLs = flags.Flags&_MicrosoftSignedOnly != 0

	if err := getProcessMitigationPolicy(cp, processDynamicCodePolicy, unsafe.Pointer(&flags), unsafe.Sizeof(flags)); err != nil {
		return result, err
	}
	result.ProhibitDynamicCode = flags.Flags&_ProhibitDynamicCode != 0

	if err := getProcessMitigationPolicy(cp, processImageLoadPolicy, unsafe.Pointer(&flags), unsafe.Sizeof(flags)); err != nil {
		return result, err
	}
	result.ProhibitRemoteImages = flags.Flags&_NoRemoteImages != 0
	result.ProhibitLowMandatoryLabelImages = flags.Flags&_NoLowMandatoryLabelImages != 0
	result.PreferSystem32Images = flags.Flags&_PreferSystem32Images != 0

	return result, nil
}

func (pmp *ProcessMitigationPolicies) SetOnCurrentProcess() error {
	if pmp.DisableExtensionPoints {
		v := processMitigationPolicyFlags{
			Flags: _DisableExtensionPoints,
		}
		if err := setProcessMitigationPolicy(processExtensionPointDisablePolicy, unsafe.Pointer(&v), unsafe.Sizeof(v)); err != nil {
			return err
		}
	}

	if pmp.ProhibitNonMicrosoftSignedDLLs {
		v := processMitigationPolicyFlags{
			Flags: _MicrosoftSignedOnly,
		}
		if err := setProcessMitigationPolicy(processSystemCallDisablePolicy, unsafe.Pointer(&v), unsafe.Sizeof(v)); err != nil {
			return err
		}
	}

	if pmp.ProhibitDynamicCode {
		v := processMitigationPolicyFlags{
			Flags: _ProhibitDynamicCode,
		}
		if err := setProcessMitigationPolicy(processDynamicCodePolicy, unsafe.Pointer(&v), unsafe.Sizeof(v)); err != nil {
			return err
		}
	}

	var imageLoadFlags uint32
	if pmp.PreferSystem32Images {
		imageLoadFlags |= _PreferSystem32Images
	}
	if pmp.ProhibitLowMandatoryLabelImages {
		imageLoadFlags |= _NoLowMandatoryLabelImages
	}
	if pmp.ProhibitRemoteImages {
		imageLoadFlags |= _NoRemoteImages
	}

	if imageLoadFlags != 0 {
		v := processMitigationPolicyFlags{
			Flags: imageLoadFlags,
		}
		if err := setProcessMitigationPolicy(processImageLoadPolicy, unsafe.Pointer(&v), unsafe.Sizeof(v)); err != nil {
			return err
		}
	}

	return nil
}

func (pmp *ProcessMitigationPolicies) asMitigationBits() (result uint64) {
	if pmp.DisableExtensionPoints {
		result |= (1 << 32)
	}
	if pmp.PreferSystem32Images {
		result |= (1 << 60)
	}
	if pmp.ProhibitDynamicCode {
		result |= (1 << 36)
	}
	if pmp.ProhibitLowMandatoryLabelImages {
		result |= (1 << 56)
	}
	if pmp.ProhibitNonMicrosoftSignedDLLs {
		result |= (1 << 44)
	}
	if pmp.ProhibitRemoteImages {
		result |= (1 << 52)
	}
	return result
}
