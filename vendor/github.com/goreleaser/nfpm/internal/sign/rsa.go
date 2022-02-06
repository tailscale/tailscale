package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // nolint:gosec
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

var (
	errNoPemBlock   = errors.New("no PEM block found")
	errDigestNotSH1 = errors.New("digest is not a SHA1 hash")
	errNoPassphrase = errors.New("key is encrypted but no passphrase was provided")
	errNoRSAKey     = errors.New("key is not an RSA key")
)

// RSASignSHA1Digest signs the provided SHA1 message digest. The key file
// must be in the PEM format and can either be encrypted or not.
func RSASignSHA1Digest(sha1Digest []byte, keyFile, passphrase string) ([]byte, error) {
	if len(sha1Digest) != sha1.Size {
		return nil, errDigestNotSH1
	}

	keyFileContent, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(keyFileContent)
	if block == nil {
		return nil, errNoPemBlock
	}

	blockData := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if passphrase == "" {
			return nil, errNoPassphrase
		}

		var decryptedBlockData []byte

		decryptedBlockData, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("decrypt private key PEM block: %w", err)
		}

		blockData = decryptedBlockData
	}

	priv, err := x509.ParsePKCS1PrivateKey(blockData)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS1 private key: %w", err)
	}

	signature, err := priv.Sign(rand.Reader, sha1Digest, crypto.SHA1)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	return signature, nil
}

func rsaSign(message io.Reader, keyFile, passphrase string) ([]byte, error) {
	sha1Hash := sha1.New() // nolint:gosec
	_, err := io.Copy(sha1Hash, message)
	if err != nil {
		return nil, fmt.Errorf("create SHA1 message digest: %w", err)
	}

	return RSASignSHA1Digest(sha1Hash.Sum(nil), keyFile, passphrase)
}

// RSAVerifySHA1Digest is exported for use in tests and verifies a signature over the
// provided SHA1 hash of a message. The key file must be in the PEM format.
func RSAVerifySHA1Digest(sha1Digest, signature []byte, publicKeyFile string) error {
	if len(sha1Digest) != sha1.Size {
		return errDigestNotSH1
	}

	keyFileContent, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(keyFileContent)
	if block == nil {
		return errNoPemBlock
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse PKIX public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errNoRSAKey
	}

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA1, sha1Digest, signature)
	if err != nil {
		return fmt.Errorf("verify PKCS1v15 signature: %w", err)
	}

	return nil
}

func rsaVerify(message io.Reader, signature []byte, publicKeyFile string) error {
	sha1Hash := sha1.New() // nolint:gosec
	_, err := io.Copy(sha1Hash, message)
	if err != nil {
		return fmt.Errorf("create SHA1 message digest: %w", err)
	}

	return RSAVerifySHA1Digest(sha1Hash.Sum(nil), signature, publicKeyFile)
}
