package certstore

import (
	"crypto"
	"crypto/x509"
	"errors"
)

var (
	// ErrUnsupportedHash is returned by Signer.Sign() when the provided hash
	// algorithm isn't supported.
	ErrUnsupportedHash = errors.New("unsupported hash algorithm")
)

// StoreLocation defines the store location to look certificates in.
type StoreLocation int

const (
	// User is the user scoped certificate store. "CURRENT_USER" on Windows or
	// "login" on MacOS
	User StoreLocation = iota
	// System is the system scoped certificate store. "LOCAL_MACHINE" on Windows
	// or "System" on MacOS
	System
)

// Open opens the system's certificate store.
func Open(location StoreLocation) (Store, error) {
	return openStore(location)
}

// Store represents the system's certificate store.
type Store interface {
	// Identities gets a list of identities from the store.
	Identities() ([]Identity, error)

	// Import imports a PKCS#12 (PFX) blob containing a certificate and private
	// key.
	Import(data []byte, password string) error

	// Close closes the store.
	Close()
}

// Identity is a X.509 certificate and its corresponding private key.
type Identity interface {
	// Certificate gets the identity's certificate.
	Certificate() (*x509.Certificate, error)

	// CertificateChain attempts to get the identity's full certificate chain.
	CertificateChain() ([]*x509.Certificate, error)

	// Signer gets a crypto.Signer that uses the identity's private key.
	Signer() (crypto.Signer, error)

	// Delete deletes this identity from the system.
	Delete() error

	// Close any manually managed memory held by the Identity.
	Close()
}
