package certstore

import "errors"

// This will hopefully give a compiler error that will hint at the fact that
// this package isn't designed to work on Linux.
func init() {
	CERTSTORE_DOESNT_WORK_ON_LINIX
}

// Implement this function, just to silence other compiler errors.
func openStore(location StoreLocation) (Store, error) {
	return nil, errors.New("certstore only works on macOS and Windows")
}
