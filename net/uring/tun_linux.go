package uring

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/tun"
)

// Wrap files into TUN devices.

func NewTUN(d tun.Device) (tun.Device, error) {
	nt, ok := d.(*tun.NativeTun)
	if !ok {
		return nil, fmt.Errorf("NewTUN only wraps *tun.NativeTun, got %T", d)
	}
	f, err := newFile(nt.File())
	if err != nil {
		return nil, err
	}
	v := reflect.ValueOf(nt)
	field, ok := v.Elem().Type().FieldByName("errors")
	if !ok {
		return nil, errors.New("could not find internal tun.NativeTun errors field")
	}
	ptr := unsafe.Pointer(nt)
	ptr = unsafe.Pointer(uintptr(ptr) + field.Offset) // TODO: switch to unsafe.Add with Go 1.17...as if that's the worst thing in this line
	c := *(*chan error)(ptr)
	return &TUN{d: nt, f: f, errors: c}, nil
}

// No nopi
type TUN struct {
	d      *tun.NativeTun
	f      *file
	errors chan error
}

func (t *TUN) File() *os.File {
	return t.f.file
}

func (t *TUN) Read(buf []byte, offset int) (int, error) {
	select {
	case err := <-t.errors:
		return 0, err
	default:
	}
	// TODO: upstream has graceful shutdown error handling here.
	buff := buf[offset-4:]
	n, err := t.f.Read(buff[:])
	if errors.Is(err, syscall.EBADFD) {
		err = os.ErrClosed
	}
	if n < 4 {
		n = 0
	} else {
		n -= 4
	}
	return n, err
}

func (t *TUN) Write(buf []byte, offset int) (int, error) {
	// below copied from wireguard-go NativeTun.Write

	// reserve space for header
	buf = buf[offset-4:]

	// add packet information header
	buf[0] = 0x00
	buf[1] = 0x00
	if buf[4]>>4 == ipv6.Version {
		buf[2] = 0x86
		buf[3] = 0xdd
	} else {
		buf[2] = 0x08
		buf[3] = 0x00
	}

	n, err := t.f.Write(buf)
	if errors.Is(err, syscall.EBADFD) {
		err = os.ErrClosed
	}
	return n, err
}

func (t *TUN) Flush() error           { return t.d.Flush() }
func (t *TUN) MTU() (int, error)      { return t.d.MTU() }
func (t *TUN) Name() (string, error)  { return t.d.Name() }
func (t *TUN) Events() chan tun.Event { return t.d.Events() }

func (t *TUN) Close() error {
	err1 := t.f.Close()
	err2 := t.d.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
