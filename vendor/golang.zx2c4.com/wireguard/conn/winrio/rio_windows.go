/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 WireGuard LLC. All Rights Reserved.
 */

package winrio

import (
	"log"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MsgDontNotify = 1
	MsgDefer      = 2
	MsgWaitAll    = 4
	MsgCommitOnly = 8

	MaxCqSize = 0x8000000

	invalidBufferId = 0xFFFFFFFF
	invalidCq       = 0
	invalidRq       = 0
	corruptCq       = 0xFFFFFFFF
)

var extensionFunctionTable struct {
	cbSize                   uint32
	rioReceive               uintptr
	rioReceiveEx             uintptr
	rioSend                  uintptr
	rioSendEx                uintptr
	rioCloseCompletionQueue  uintptr
	rioCreateCompletionQueue uintptr
	rioCreateRequestQueue    uintptr
	rioDequeueCompletion     uintptr
	rioDeregisterBuffer      uintptr
	rioNotify                uintptr
	rioRegisterBuffer        uintptr
	rioResizeCompletionQueue uintptr
	rioResizeRequestQueue    uintptr
}

type Cq uintptr

type Rq uintptr

type BufferId uintptr

type Buffer struct {
	Id     BufferId
	Offset uint32
	Length uint32
}

type Result struct {
	Status           int32
	BytesTransferred uint32
	SocketContext    uint64
	RequestContext   uint64
}

type notificationCompletionType uint32

const (
	eventCompletion notificationCompletionType = 1
	iocpCompletion  notificationCompletionType = 2
)

type eventNotificationCompletion struct {
	completionType notificationCompletionType
	event          windows.Handle
	notifyReset    uint32
}

type iocpNotificationCompletion struct {
	completionType notificationCompletionType
	iocp           windows.Handle
	key            uintptr
	overlapped     *windows.Overlapped
}

var initialized sync.Once
var available bool

func Initialize() bool {
	initialized.Do(func() {
		var (
			err    error
			socket windows.Handle
			cq     Cq
		)
		defer func() {
			if err == nil {
				return
			}
			if maj, _, _ := windows.RtlGetNtVersionNumbers(); maj <= 7 {
				return
			}
			log.Printf("Registered I/O is unavailable: %v", err)
		}()
		socket, err = Socket(windows.AF_INET, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
		if err != nil {
			return
		}
		defer windows.CloseHandle(socket)
		var WSAID_MULTIPLE_RIO = &windows.GUID{0x8509e081, 0x96dd, 0x4005, [8]byte{0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f}}
		const SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER = 0xc8000024
		ob := uint32(0)
		err = windows.WSAIoctl(socket, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
			(*byte)(unsafe.Pointer(WSAID_MULTIPLE_RIO)), uint32(unsafe.Sizeof(*WSAID_MULTIPLE_RIO)),
			(*byte)(unsafe.Pointer(&extensionFunctionTable)), uint32(unsafe.Sizeof(extensionFunctionTable)),
			&ob, nil, 0)
		if err != nil {
			return
		}

		// While we should be able to stop here, after getting the function pointers, some anti-virus actually causes
		// failures in RIOCreateRequestQueue, so keep going to be certain this is supported.
		var iocp windows.Handle
		iocp, err = windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 0)
		if err != nil {
			return
		}
		defer windows.CloseHandle(iocp)
		var overlapped windows.Overlapped
		cq, err = CreateIOCPCompletionQueue(2, iocp, 0, &overlapped)
		if err != nil {
			return
		}
		defer CloseCompletionQueue(cq)
		_, err = CreateRequestQueue(socket, 1, 1, 1, 1, cq, cq, 0)
		if err != nil {
			return
		}
		available = true
	})
	return available
}

func Socket(af, typ, proto int32) (windows.Handle, error) {
	return windows.WSASocket(af, typ, proto, nil, 0, windows.WSA_FLAG_REGISTERED_IO)
}

func CloseCompletionQueue(cq Cq) {
	_, _, _ = syscall.Syscall(extensionFunctionTable.rioCloseCompletionQueue, 1, uintptr(cq), 0, 0)
}

func CreateEventCompletionQueue(queueSize uint32, event windows.Handle, notifyReset bool) (Cq, error) {
	notificationCompletion := &eventNotificationCompletion{
		completionType: eventCompletion,
		event:          event,
	}
	if notifyReset {
		notificationCompletion.notifyReset = 1
	}
	ret, _, err := syscall.Syscall(extensionFunctionTable.rioCreateCompletionQueue, 2, uintptr(queueSize), uintptr(unsafe.Pointer(notificationCompletion)), 0)
	if ret == invalidCq {
		return 0, err
	}
	return Cq(ret), nil
}

func CreateIOCPCompletionQueue(queueSize uint32, iocp windows.Handle, key uintptr, overlapped *windows.Overlapped) (Cq, error) {
	notificationCompletion := &iocpNotificationCompletion{
		completionType: iocpCompletion,
		iocp:           iocp,
		key:            key,
		overlapped:     overlapped,
	}
	ret, _, err := syscall.Syscall(extensionFunctionTable.rioCreateCompletionQueue, 2, uintptr(queueSize), uintptr(unsafe.Pointer(notificationCompletion)), 0)
	if ret == invalidCq {
		return 0, err
	}
	return Cq(ret), nil
}

func CreatePolledCompletionQueue(queueSize uint32) (Cq, error) {
	ret, _, err := syscall.Syscall(extensionFunctionTable.rioCreateCompletionQueue, 2, uintptr(queueSize), 0, 0)
	if ret == invalidCq {
		return 0, err
	}
	return Cq(ret), nil
}

func CreateRequestQueue(socket windows.Handle, maxOutstandingReceive, maxReceiveDataBuffers, maxOutstandingSend, maxSendDataBuffers uint32, receiveCq, sendCq Cq, socketContext uintptr) (Rq, error) {
	ret, _, err := syscall.Syscall9(extensionFunctionTable.rioCreateRequestQueue, 8, uintptr(socket), uintptr(maxOutstandingReceive), uintptr(maxReceiveDataBuffers), uintptr(maxOutstandingSend), uintptr(maxSendDataBuffers), uintptr(receiveCq), uintptr(sendCq), socketContext, 0)
	if ret == invalidRq {
		return 0, err
	}
	return Rq(ret), nil
}

func DequeueCompletion(cq Cq, results []Result) uint32 {
	var array uintptr
	if len(results) > 0 {
		array = uintptr(unsafe.Pointer(&results[0]))
	}
	ret, _, _ := syscall.Syscall(extensionFunctionTable.rioDequeueCompletion, 3, uintptr(cq), array, uintptr(len(results)))
	if ret == corruptCq {
		panic("cq is corrupt")
	}
	return uint32(ret)
}

func DeregisterBuffer(id BufferId) {
	_, _, _ = syscall.Syscall(extensionFunctionTable.rioDeregisterBuffer, 1, uintptr(id), 0, 0)
}

func RegisterBuffer(buffer []byte) (BufferId, error) {
	var buf unsafe.Pointer
	if len(buffer) > 0 {
		buf = unsafe.Pointer(&buffer[0])
	}
	return RegisterPointer(buf, uint32(len(buffer)))
}

func RegisterPointer(ptr unsafe.Pointer, size uint32) (BufferId, error) {
	ret, _, err := syscall.Syscall(extensionFunctionTable.rioRegisterBuffer, 2, uintptr(ptr), uintptr(size), 0)
	if ret == invalidBufferId {
		return 0, err
	}
	return BufferId(ret), nil
}

func SendEx(rq Rq, buf *Buffer, dataBufferCount uint32, localAddress, remoteAddress, controlContext, flags *Buffer, sflags uint32, requestContext uintptr) error {
	ret, _, err := syscall.Syscall9(extensionFunctionTable.rioSendEx, 9, uintptr(rq), uintptr(unsafe.Pointer(buf)), uintptr(dataBufferCount), uintptr(unsafe.Pointer(localAddress)), uintptr(unsafe.Pointer(remoteAddress)), uintptr(unsafe.Pointer(controlContext)), uintptr(unsafe.Pointer(flags)), uintptr(sflags), requestContext)
	if ret == 0 {
		return err
	}
	return nil
}

func ReceiveEx(rq Rq, buf *Buffer, dataBufferCount uint32, localAddress, remoteAddress, controlContext, flags *Buffer, sflags uint32, requestContext uintptr) error {
	ret, _, err := syscall.Syscall9(extensionFunctionTable.rioReceiveEx, 9, uintptr(rq), uintptr(unsafe.Pointer(buf)), uintptr(dataBufferCount), uintptr(unsafe.Pointer(localAddress)), uintptr(unsafe.Pointer(remoteAddress)), uintptr(unsafe.Pointer(controlContext)), uintptr(unsafe.Pointer(flags)), uintptr(sflags), requestContext)
	if ret == 0 {
		return err
	}
	return nil
}

func Notify(cq Cq) error {
	ret, _, _ := syscall.Syscall(extensionFunctionTable.rioNotify, 1, uintptr(cq), 0, 0)
	if ret != 0 {
		return windows.Errno(ret)
	}
	return nil
}
