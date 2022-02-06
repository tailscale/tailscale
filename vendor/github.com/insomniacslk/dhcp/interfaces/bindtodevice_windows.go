package interfaces

import "errors"

// BindToInterface fails on Windows.
func BindToInterface(fd int, ifname string) error {
	return errors.New("not implemented on Windows")
}
