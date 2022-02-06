//go:build gofuzz
// +build gofuzz

package rtnetlink

// FuzzLinkMessage will fuzz a LinkMessage
func FuzzLinkMessage(data []byte) int {
	m := &LinkMessage{}
	if err := (m).UnmarshalBinary(data); err != nil {
		return 0
	}

	if _, err := m.MarshalBinary(); err != nil {
		panic(err)
	}

	return 1
}

// FuzzAddressMessage will fuzz an AddressMessage
func FuzzAddressMessage(data []byte) int {
	m := &AddressMessage{}
	if err := (m).UnmarshalBinary(data); err != nil {
		return 0
	}

	if _, err := m.MarshalBinary(); err != nil {
		panic(err)
	}

	return 1
}

// FuzzRouteMessage will fuzz a RouteMessage
func FuzzRouteMessage(data []byte) int {
	m := &RouteMessage{}
	if err := (m).UnmarshalBinary(data); err != nil {
		return 0
	}

	if _, err := m.MarshalBinary(); err != nil {
		panic(err)
	}

	return 1
}

// FuzzNeighMessage will fuzz a NeighMessage
func FuzzNeighMessage(data []byte) int {
	m := &NeighMessage{}
	if err := (m).UnmarshalBinary(data); err != nil {
		return 0
	}

	if _, err := m.MarshalBinary(); err != nil {
		panic(err)
	}

	return 1
}
