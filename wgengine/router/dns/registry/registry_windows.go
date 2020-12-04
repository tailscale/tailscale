// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// The code in this file is copied from:
// Copyright (C) 2020 WireGuard LLC. All Rights Reserved.

// TODO(peske): Check the file header ^^^ to ensure appropriate copyright info.
package registry

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// REG_NOTIFY_CHANGE_NAME notifies the caller if a subkey is added or deleted.
	REG_NOTIFY_CHANGE_NAME uint32 = 0x00000001

	// REG_NOTIFY_CHANGE_ATTRIBUTES notifies the caller of changes to the attributes of the key, such as the security descriptor information.
	REG_NOTIFY_CHANGE_ATTRIBUTES uint32 = 0x00000002

	// REG_NOTIFY_CHANGE_LAST_SET notifies the caller of changes to a value of the key. This can include adding or deleting a value, or changing an existing value.
	REG_NOTIFY_CHANGE_LAST_SET uint32 = 0x00000004

	// REG_NOTIFY_CHANGE_SECURITY notifies the caller of changes to the security descriptor of the key.
	REG_NOTIFY_CHANGE_SECURITY uint32 = 0x00000008

	// REG_NOTIFY_THREAD_AGNOSTIC indicates that the lifetime of the registration must not be tied to the lifetime of the thread issuing the RegNotifyChangeKeyValue call. Note: This flag value is only supported in Windows 8 and later.
	REG_NOTIFY_THREAD_AGNOSTIC uint32 = 0x10000000
)

//sys	regNotifyChangeKeyValue(key windows.Handle, watchSubtree bool, notifyFilter uint32, event windows.Handle, asynchronous bool) (regerrno error) = advapi32.RegNotifyChangeKeyValue

func OpenKeyWait(k registry.Key, path string, access uint32, timeout time.Duration) (registry.Key, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	deadline := time.Now().Add(timeout)
	pathSpl := strings.Split(path, "\\")
	for i := 0; ; i++ {
		keyName := pathSpl[i]
		isLast := i+1 == len(pathSpl)

		event, err := windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			return 0, fmt.Errorf("Error creating event: %v", err)
		}
		defer windows.CloseHandle(event)

		var key registry.Key
		for {
			err = regNotifyChangeKeyValue(windows.Handle(k), false, REG_NOTIFY_CHANGE_NAME, windows.Handle(event), true)
			if err != nil {
				return 0, fmt.Errorf("Setting up change notification on registry key failed: %v", err)
			}

			var accessFlags uint32
			if isLast {
				accessFlags = access
			} else {
				accessFlags = registry.NOTIFY
			}
			key, err = registry.OpenKey(k, keyName, accessFlags)
			if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
				timeout := time.Until(deadline) / time.Millisecond
				if timeout < 0 {
					timeout = 0
				}
				s, err := windows.WaitForSingleObject(event, uint32(timeout))
				if err != nil {
					return 0, fmt.Errorf("Unable to wait on registry key: %v", err)
				}
				if s == uint32(windows.WAIT_TIMEOUT) { // windows.WAIT_TIMEOUT status const is misclassified as error in golang.org/x/sys/windows
					return 0, errors.New("Timeout waiting for registry key")
				}
			} else if err != nil {
				return 0, fmt.Errorf("Error opening registry key %v: %v", path, err)
			} else {
				if isLast {
					return key, nil
				}
				defer key.Close()
				break
			}
		}

		k = key
	}
}

func WaitForKey(k registry.Key, path string, timeout time.Duration) error {
	key, err := OpenKeyWait(k, path, registry.NOTIFY, timeout)
	if err != nil {
		return err
	}
	key.Close()
	return nil
}

//
// getValue is more or less the same as windows/registry's getValue.
//
func getValue(k registry.Key, name string, buf []byte) (value []byte, valueType uint32, err error) {
	var name16 *uint16
	name16, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	n := uint32(len(buf))
	for {
		err = windows.RegQueryValueEx(windows.Handle(k), name16, nil, &valueType, (*byte)(unsafe.Pointer(&buf[0])), &n)
		if err == nil {
			value = buf[:n]
			return
		}
		if err != windows.ERROR_MORE_DATA {
			return
		}
		if n <= uint32(len(buf)) {
			return
		}
		buf = make([]byte, n)
	}
}

//
// getValueRetry function reads any value from registry. It waits for
// the registry value to become available or returns error on timeout.
//
// Key must be opened with at least QUERY_VALUE|NOTIFY access.
//
func getValueRetry(key registry.Key, name string, buf []byte, timeout time.Duration) ([]byte, uint32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("Error creating event: %v", err)
	}
	defer windows.CloseHandle(event)

	deadline := time.Now().Add(timeout)
	for {
		err := regNotifyChangeKeyValue(windows.Handle(key), false, REG_NOTIFY_CHANGE_LAST_SET, windows.Handle(event), true)
		if err != nil {
			return nil, 0, fmt.Errorf("Setting up change notification on registry value failed: %v", err)
		}

		buf, valueType, err := getValue(key, name, buf)
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			timeout := time.Until(deadline) / time.Millisecond
			if timeout < 0 {
				timeout = 0
			}
			s, err := windows.WaitForSingleObject(event, uint32(timeout))
			if err != nil {
				return nil, 0, fmt.Errorf("Unable to wait on registry value: %v", err)
			}
			if s == uint32(windows.WAIT_TIMEOUT) { // windows.WAIT_TIMEOUT status const is misclassified as error in golang.org/x/sys/windows
				return nil, 0, errors.New("Timeout waiting for registry value")
			}
		} else if err != nil {
			return nil, 0, fmt.Errorf("Error reading registry value %v: %v", name, err)
		} else {
			return buf, valueType, nil
		}
	}
}

func toString(buf []byte, valueType uint32, err error) (string, error) {
	if err != nil {
		return "", err
	}

	var value string
	switch valueType {
	case registry.SZ, registry.EXPAND_SZ, registry.MULTI_SZ:
		if len(buf) == 0 {
			return "", nil
		}
		value = windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&buf[0])))

	default:
		return "", registry.ErrUnexpectedType
	}

	if valueType != registry.EXPAND_SZ {
		// Value does not require expansion.
		return value, nil
	}

	valueExp, err := registry.ExpandString(value)
	if err != nil {
		// Expanding failed: return original sting value.
		return value, nil
	}

	// Return expanded value.
	return valueExp, nil
}

func toInteger(buf []byte, valueType uint32, err error) (uint64, error) {
	if err != nil {
		return 0, err
	}

	switch valueType {
	case registry.DWORD:
		if len(buf) != 4 {
			return 0, errors.New("DWORD value is not 4 bytes long")
		}
		var val uint32
		copy((*[4]byte)(unsafe.Pointer(&val))[:], buf)
		return uint64(val), nil

	case registry.QWORD:
		if len(buf) != 8 {
			return 0, errors.New("QWORD value is not 8 bytes long")
		}
		var val uint64
		copy((*[8]byte)(unsafe.Pointer(&val))[:], buf)
		return val, nil

	default:
		return 0, registry.ErrUnexpectedType
	}
}

//
// GetStringValueWait function reads a string value from registry. It waits
// for the registry value to become available or returns error on timeout.
//
// Key must be opened with at least QUERY_VALUE|NOTIFY access.
//
// If the value type is REG_EXPAND_SZ the environment variables are expanded.
// Should expanding fail, original string value and nil error are returned.
//
// If the value type is REG_MULTI_SZ only the first string is returned.
//
func GetStringValueWait(key registry.Key, name string, timeout time.Duration) (string, error) {
	return toString(getValueRetry(key, name, make([]byte, 256), timeout))
}

//
// GetStringValue function reads a string value from registry.
//
// Key must be opened with at least QUERY_VALUE access.
//
// If the value type is REG_EXPAND_SZ the environment variables are expanded.
// Should expanding fail, original string value and nil error are returned.
//
// If the value type is REG_MULTI_SZ only the first string is returned.
//
func GetStringValue(key registry.Key, name string) (string, error) {
	return toString(getValue(key, name, make([]byte, 256)))
}

//
// GetIntegerValueWait function reads a DWORD32 or QWORD value from registry.
// It waits for the registry value to become available or returns error on
// timeout.
//
// Key must be opened with at least QUERY_VALUE|NOTIFY access.
//
func GetIntegerValueWait(key registry.Key, name string, timeout time.Duration) (uint64, error) {
	return toInteger(getValueRetry(key, name, make([]byte, 8), timeout))
}
