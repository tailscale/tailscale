// Code generated by 'go generate'; DO NOT EDIT.

package registry

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procRegNotifyChangeKeyValue = modadvapi32.NewProc("RegNotifyChangeKeyValue")
)

func regNotifyChangeKeyValue(key windows.Handle, watchSubtree bool, notifyFilter uint32, event windows.Handle, asynchronous bool) (regerrno error) {
	var _p0 uint32
	if watchSubtree {
		_p0 = 1
	}
	var _p1 uint32
	if asynchronous {
		_p1 = 1
	}
	r0, _, _ := syscall.Syscall6(procRegNotifyChangeKeyValue.Addr(), 5, uintptr(key), uintptr(_p0), uintptr(notifyFilter), uintptr(event), uintptr(_p1), 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}
