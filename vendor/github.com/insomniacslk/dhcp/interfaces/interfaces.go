package interfaces

import "net"

// InterfaceMatcher is a function type used to match the interfaces we want. See
// GetInterfacesFunc below for usage.
type InterfaceMatcher func(net.Interface) bool

// interfaceGetter is used for testing purposes
var interfaceGetter = net.Interfaces

// GetInterfacesFunc loops through the available network interfaces, and returns
// a list of interfaces for which the passed InterfaceMatcher function returns
// true.
func GetInterfacesFunc(matcher InterfaceMatcher) ([]net.Interface, error) {
	ifaces, err := interfaceGetter()
	if err != nil {
		return nil, err
	}
	ret := make([]net.Interface, 0)
	for _, iface := range ifaces {
		if matcher(iface) {
			ret = append(ret, iface)
		}
	}
	return ret, nil
}

// GetLoopbackInterfaces returns a list of loopback interfaces.
func GetLoopbackInterfaces() ([]net.Interface, error) {
	return GetInterfacesFunc(func(iface net.Interface) bool {
		return iface.Flags&net.FlagLoopback != 0
	})
}

// GetNonLoopbackInterfaces returns a list of non-loopback interfaces.
func GetNonLoopbackInterfaces() ([]net.Interface, error) {
	return GetInterfacesFunc(func(iface net.Interface) bool {
		return iface.Flags&net.FlagLoopback == 0
	})
}
