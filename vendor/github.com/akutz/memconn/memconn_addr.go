package memconn

// Addr represents the address of an in-memory endpoint.
type Addr struct {
	// Name is the name of the endpoint.
	Name string

	network string
}

// Buffered indicates whether or not the address refers to a buffered
// network type.
func (a Addr) Buffered() bool {
	return a.network == networkMemb
}

// Network returns the address's network.
func (a Addr) Network() string {
	return a.network
}

// String returns the address's name.
func (a Addr) String() string {
	return a.Name
}
