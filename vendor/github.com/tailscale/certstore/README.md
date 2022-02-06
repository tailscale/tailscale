# certstore [![PkgGoDev](https://pkg.go.dev/badge/github.com/github/certstore?tab=doc)](https://pkg.go.dev/github.com/github/certstore?tab=doc) [![Report card](https://goreportcard.com/badge/github.com/github/certstore)](https://goreportcard.com/report/github.com/github/certstore) [![AppVeyor Windows Build status](https://ci.appveyor.com/api/projects/status/github/github/certstore?branch=main&svg=true)](https://ci.appveyor.com/project/github/certstore/branch/main)

[![Test macOS (recent Go versions)](<https://github.com/github/certstore/workflows/Test%20macOS%20(recent%20Go%20versions)/badge.svg>)](https://github.com/github/certstore/actions?query=workflow%3A%22Test+macOS+%28recent+Go+versions%29%22)  
[![Test macOS (Go 1.8)](<https://github.com/github/certstore/workflows/Test%20macOS%20(Go%201.8)/badge.svg>)](https://github.com/github/certstore/actions?query=workflow%3A%22Test+macOS+%28Go+1.8%29%22)  
[![Test Windows (recent Go versions)](<https://github.com/github/certstore/workflows/Test%20Windows%20(recent%20Go%20versions)/badge.svg>)](https://github.com/github/certstore/actions?query=workflow%3A%22Test+Windows+%28recent+Go+versions%29%22)  
[![Test Windows (Go 1.8)](<https://github.com/github/certstore/workflows/Test%20Windows%20(Go%201.8)/badge.svg>)](https://github.com/github/certstore/actions?query=workflow%3A%22Test+Windows+%28Go+1.8%29%22)

Certstore is a Go library for accessing user identities stored in platform certificate stores. On Windows and macOS, certstore can enumerate user identities and sign messages with their private keys.

## Example

```go
package main

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"

	"crypto/rand"
	"crypto/sha256"

	"github.com/github/certstore"
)

func main() {
	sig, err := signWithMyIdentity("Ben Toews", "hello, world!")
	if err != nil {
		panic(err)
	}

	fmt.Println(hex.EncodeToString(sig))
}

func signWithMyIdentity(cn, msg string) ([]byte, error) {
	// Open the certificate store for use. This must be Close()'ed once you're
	// finished with the store and any identities it contains.
	store, err := certstore.Open()
	if err != nil {
		return nil, err
	}
	defer store.Close()

	// Get an Identity slice, containing every identity in the store. Each of
	// these must be Close()'ed when you're done with them.
	idents, err := store.Identities()
	if err != nil {
		return nil, err
	}

	// Iterate through the identities, looking for the one we want.
	var me certstore.Identity
	for _, ident := range idents {
		defer ident.Close()

		crt, errr := ident.Certificate()
		if errr != nil {
			return nil, errr
		}

		if crt.Subject.CommonName == "Ben Toews" {
			me = ident
		}
	}

	if me == nil {
		return nil, errors.New("Couldn't find my identity")
	}

	// Get a crypto.Signer for the identity.
	signer, err := me.Signer()
	if err != nil {
		return nil, err
	}

	// Digest and sign our message.
	digest := sha256.Sum256([]byte(msg))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

```
