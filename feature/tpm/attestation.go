// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tpm

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"tailscale.com/types/key"
)

type attestationKey struct {
	tpm transport.TPMCloser
	// private and public parts of the TPM key as returned from tpm2.Create.
	// These are used for serialization.
	tpmPrivate tpm2.TPM2BPrivate
	tpmPublic  tpm2.TPM2BPublic
	// handle of the loaded TPM key.
	handle *tpm2.NamedHandle
	// pub is the parsed *ecdsa.PublicKey.
	pub crypto.PublicKey
}

func newAttestationKey() (ak *attestationKey, retErr error) {
	tpm, err := open()
	if err != nil {
		return nil, key.ErrUnsupported
	}
	defer func() {
		if retErr != nil {
			tpm.Close()
		}
	}()
	ak = &attestationKey{tpm: tpm}

	// Create a key under the storage hierarchy.
	if err := withSRK(log.Printf, ak.tpm, func(srk tpm2.AuthHandle) error {
		resp, err := tpm2.Create{
			ParentHandle: tpm2.NamedHandle{
				Handle: srk.Handle,
				Name:   srk.Name,
			},
			InPublic: tpm2.New2B(
				tpm2.TPMTPublic{
					Type:    tpm2.TPMAlgECC,
					NameAlg: tpm2.TPMAlgSHA256,
					ObjectAttributes: tpm2.TPMAObject{
						SensitiveDataOrigin: true,
						UserWithAuth:        true,
						AdminWithPolicy:     true,
						NoDA:                true,
						FixedTPM:            true,
						FixedParent:         true,
						SignEncrypt:         true,
					},
					Parameters: tpm2.NewTPMUPublicParms(
						tpm2.TPMAlgECC,
						&tpm2.TPMSECCParms{
							CurveID: tpm2.TPMECCNistP256,
							Scheme: tpm2.TPMTECCScheme{
								Scheme: tpm2.TPMAlgECDSA,
								Details: tpm2.NewTPMUAsymScheme(
									tpm2.TPMAlgECDSA,
									&tpm2.TPMSSigSchemeECDSA{
										// Unfortunately, TPMs don't let us use
										// TPMAlgNull here to make the hash
										// algorithm dynamic higher in the
										// stack. We have to hardcode it here.
										HashAlg: tpm2.TPMAlgSHA256,
									},
								),
							},
						},
					),
				},
			),
		}.Execute(ak.tpm)
		if err != nil {
			return fmt.Errorf("tpm2.Create: %w", err)
		}
		ak.tpmPrivate = resp.OutPrivate
		ak.tpmPublic = resp.OutPublic
		return nil
	}); err != nil {
		return nil, err
	}
	return ak, ak.load()
}

func (ak *attestationKey) loaded() bool {
	return ak.tpm != nil && ak.handle != nil && ak.pub != nil
}

// load the key into the TPM from its public/private components. Must be called
// before Sign or Public.
func (ak *attestationKey) load() error {
	if ak.loaded() {
		return nil
	}
	if len(ak.tpmPrivate.Buffer) == 0 || len(ak.tpmPublic.Bytes()) == 0 {
		return fmt.Errorf("attestationKey.load called without tpmPrivate or tpmPublic")
	}
	return withSRK(log.Printf, ak.tpm, func(srk tpm2.AuthHandle) error {
		resp, err := tpm2.Load{
			ParentHandle: tpm2.NamedHandle{
				Handle: srk.Handle,
				Name:   srk.Name,
			},
			InPrivate: ak.tpmPrivate,
			InPublic:  ak.tpmPublic,
		}.Execute(ak.tpm)
		if err != nil {
			return fmt.Errorf("tpm2.Load: %w", err)
		}

		ak.handle = &tpm2.NamedHandle{
			Handle: resp.ObjectHandle,
			Name:   resp.Name,
		}
		pub, err := ak.tpmPublic.Contents()
		if err != nil {
			return err
		}
		ak.pub, err = tpm2.Pub(*pub)
		return err
	})
}

// attestationKeySerialized is the JSON-serialized representation of
// attestationKey.
type attestationKeySerialized struct {
	TPMPrivate []byte `json:"tpmPrivate"`
	TPMPublic  []byte `json:"tpmPublic"`
}

func (ak *attestationKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(attestationKeySerialized{
		TPMPublic:  ak.tpmPublic.Bytes(),
		TPMPrivate: ak.tpmPrivate.Buffer,
	})
}

func (ak *attestationKey) UnmarshalJSON(data []byte) (retErr error) {
	var aks attestationKeySerialized
	if err := json.Unmarshal(data, &aks); err != nil {
		return err
	}

	ak.tpmPrivate = tpm2.TPM2BPrivate{Buffer: aks.TPMPrivate}
	ak.tpmPublic = tpm2.BytesAs2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](aks.TPMPublic)

	tpm, err := open()
	if err != nil {
		return key.ErrUnsupported
	}
	defer func() {
		if retErr != nil {
			tpm.Close()
		}
	}()
	ak.tpm = tpm

	return ak.load()
}

func (ak *attestationKey) Public() crypto.PublicKey {
	return ak.pub
}

func (ak *attestationKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if !ak.loaded() {
		return nil, errors.New("tpm2 attestation key is not loaded during Sign")
	}
	// Unfortunately, TPMs don't let us make keys with dynamic hash algorithms.
	// The hash algorithm is fixed at key creation time (tpm2.Create).
	if opts != crypto.SHA256 {
		return nil, fmt.Errorf("tpm2 key is restricted to SHA256, have %q", opts)
	}
	resp, err := tpm2.Sign{
		KeyHandle: ak.handle,
		Digest: tpm2.TPM2BDigest{
			Buffer: digest,
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}.Execute(ak.tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2.Sign: %w", err)
	}
	sig, err := resp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	return encodeSignature(sig.SignatureR.Buffer, sig.SignatureS.Buffer)
}

// Copied from crypto/ecdsa.
func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes encodes in ASN.1 a positive integer represented as
// a big-endian byte slice with zero or more leading zeroes.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

func (ak *attestationKey) Close() error {
	var errs []error
	if ak.handle != nil && ak.tpm != nil {
		_, err := tpm2.FlushContext{FlushHandle: ak.handle.Handle}.Execute(ak.tpm)
		errs = append(errs, err)
	}
	if ak.tpm != nil {
		errs = append(errs, ak.tpm.Close())
	}
	return errors.Join(errs...)
}

func (ak *attestationKey) Clone() key.HardwareAttestationKey {
	return &attestationKey{
		tpm:        ak.tpm,
		tpmPrivate: ak.tpmPrivate,
		tpmPublic:  ak.tpmPublic,
		handle:     ak.handle,
		pub:        ak.pub,
	}
}
