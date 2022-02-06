// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"

	"golang.org/x/crypto/pbkdf2"
	"software.sslmate.com/src/go-pkcs12/internal/rc2"
)

var (
	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 3})
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 6})
	oidPBES2                         = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 5, 13})
	oidPBKDF2                        = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 5, 12})
	oidHmacWithSHA1                  = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 7})
	oidHmacWithSHA256                = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 9})
	oidAES256CBC                     = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 1, 42})
)

// pbeCipher is an abstraction of a PKCS#12 cipher.
type pbeCipher interface {
	// create returns a cipher.Block given a key.
	create(key []byte) (cipher.Block, error)
	// deriveKey returns a key derived from the given password and salt.
	deriveKey(salt, password []byte, iterations int) []byte
	// deriveKey returns an IV derived from the given password and salt.
	deriveIV(salt, password []byte, iterations int) []byte
}

type shaWithTripleDESCBC struct{}

func (shaWithTripleDESCBC) create(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key)
}

func (shaWithTripleDESCBC) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 1, 24)
}

func (shaWithTripleDESCBC) deriveIV(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 2, 8)
}

type shaWith40BitRC2CBC struct{}

func (shaWith40BitRC2CBC) create(key []byte) (cipher.Block, error) {
	return rc2.New(key, len(key)*8)
}

func (shaWith40BitRC2CBC) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 1, 5)
}

func (shaWith40BitRC2CBC) deriveIV(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 2, 8)
}

type pbeParams struct {
	Salt       []byte
	Iterations int
}

func pbeCipherFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.Block, []byte, error) {
	var cipherType pbeCipher

	switch {
	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC):
		cipherType = shaWithTripleDESCBC{}
	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		cipherType = shaWith40BitRC2CBC{}
	case algorithm.Algorithm.Equal(oidPBES2):
		// rfc7292#appendix-B.1 (the original PKCS#12 PBE) requires passwords formatted as BMPStrings.
		// However, rfc8018#section-3 recommends that the password for PBES2 follow ASCII or UTF-8.
		// This is also what Windows expects.
		// Therefore, we convert the password to UTF-8.
		originalPassword, err := decodeBMPString(password)
		if err != nil {
			return nil, nil, err
		}
		utf8Password := []byte(originalPassword)
		return pbes2CipherFor(algorithm, utf8Password)
	default:
		return nil, nil, NotImplementedError("algorithm " + algorithm.Algorithm.String() + " is not supported")
	}

	var params pbeParams
	if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, nil, err
	}

	key := cipherType.deriveKey(params.Salt, password, params.Iterations)
	iv := cipherType.deriveIV(params.Salt, password, params.Iterations)

	block, err := cipherType.create(key)
	if err != nil {
		return nil, nil, err
	}

	return block, iv, nil
}

func pbDecrypterFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.BlockMode, int, error) {
	block, iv, err := pbeCipherFor(algorithm, password)
	if err != nil {
		return nil, 0, err
	}

	return cipher.NewCBCDecrypter(block, iv), block.BlockSize(), nil
}

func pbDecrypt(info decryptable, password []byte) (decrypted []byte, err error) {
	cbc, blockSize, err := pbDecrypterFor(info.Algorithm(), password)
	if err != nil {
		return nil, err
	}

	encrypted := info.Data()
	if len(encrypted) == 0 {
		return nil, errors.New("pkcs12: empty encrypted data")
	}
	if len(encrypted)%blockSize != 0 {
		return nil, errors.New("pkcs12: input is not a multiple of the block size")
	}
	decrypted = make([]byte, len(encrypted))
	cbc.CryptBlocks(decrypted, encrypted)

	psLen := int(decrypted[len(decrypted)-1])
	if psLen == 0 || psLen > blockSize {
		return nil, ErrDecryption
	}

	if len(decrypted) < psLen {
		return nil, ErrDecryption
	}
	ps := decrypted[len(decrypted)-psLen:]
	decrypted = decrypted[:len(decrypted)-psLen]
	if bytes.Compare(ps, bytes.Repeat([]byte{byte(psLen)}, psLen)) != 0 {
		return nil, ErrDecryption
	}

	return
}

// PBES2-params ::= SEQUENCE {
// 	keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
// 	encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
// }
type pbes2Params struct {
	Kdf              pkix.AlgorithmIdentifier
	EncryptionScheme pkix.AlgorithmIdentifier
}

// PBKDF2-params ::= SEQUENCE {
//     salt CHOICE {
//       specified OCTET STRING,
//       otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
//     },
//     iterationCount INTEGER (1..MAX),
//     keyLength INTEGER (1..MAX) OPTIONAL,
//     prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
//     algid-hmacWithSHA1
// }
type pbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int `asn1:"optional"`
	Prf        pkix.AlgorithmIdentifier
}

func pbes2CipherFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.Block, []byte, error) {
	var params pbes2Params
	if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, nil, err
	}

	if !params.Kdf.Algorithm.Equal(oidPBKDF2) {
		return nil, nil, NotImplementedError("kdf algorithm " + params.Kdf.Algorithm.String() + " is not supported")
	}

	var kdfParams pbkdf2Params
	if err := unmarshal(params.Kdf.Parameters.FullBytes, &kdfParams); err != nil {
		return nil, nil, err
	}
	if kdfParams.Salt.Tag != asn1.TagOctetString {
		return nil, nil, errors.New("pkcs12: only octet string salts are supported for pbkdf2")
	}

	var prf func() hash.Hash
	switch {
	case kdfParams.Prf.Algorithm.Equal(oidHmacWithSHA256):
		prf = sha256.New
	case kdfParams.Prf.Algorithm.Equal(oidHmacWithSHA1):
		prf = sha1.New
	case kdfParams.Prf.Algorithm.Equal(asn1.ObjectIdentifier([]int{})):
		prf = sha1.New
	}

	key := pbkdf2.Key(password, kdfParams.Salt.Bytes, kdfParams.Iterations, 32, prf)
	iv := params.EncryptionScheme.Parameters.Bytes

	var block cipher.Block
	switch {
	case params.EncryptionScheme.Algorithm.Equal(oidAES256CBC):
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, err
		}
		block = b
	default:
		return nil, nil, NotImplementedError("pbes2 algorithm " + params.EncryptionScheme.Algorithm.String() + " is not supported")
	}
	return block, iv, nil
}

// decryptable abstracts an object that contains ciphertext.
type decryptable interface {
	Algorithm() pkix.AlgorithmIdentifier
	Data() []byte
}

func pbEncrypterFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.BlockMode, int, error) {
	block, iv, err := pbeCipherFor(algorithm, password)
	if err != nil {
		return nil, 0, err
	}

	return cipher.NewCBCEncrypter(block, iv), block.BlockSize(), nil
}

func pbEncrypt(info encryptable, decrypted []byte, password []byte) error {
	cbc, blockSize, err := pbEncrypterFor(info.Algorithm(), password)
	if err != nil {
		return err
	}

	psLen := blockSize - len(decrypted)%blockSize
	encrypted := make([]byte, len(decrypted)+psLen)
	copy(encrypted[:len(decrypted)], decrypted)
	copy(encrypted[len(decrypted):], bytes.Repeat([]byte{byte(psLen)}, psLen))
	cbc.CryptBlocks(encrypted, encrypted)

	info.SetData(encrypted)

	return nil
}

// encryptable abstracts a object that contains ciphertext.
type encryptable interface {
	Algorithm() pkix.AlgorithmIdentifier
	SetData([]byte)
}
