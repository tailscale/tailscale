package certstore

/*
#cgo windows LDFLAGS: -lcrypt32 -lncrypt

#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>

char* errMsg(DWORD code) {
	char* lpMsgBuf;
	DWORD ret = 0;

	ret = FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			code,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR) &lpMsgBuf,
			0, NULL);

	if (ret == 0) {
		return NULL;
	} else {
		return lpMsgBuf;
	}
}
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"unicode/utf16"
	"unsafe"

	"github.com/pkg/errors"
)

const (
	winTrue  C.WINBOOL = 1
	winFalse C.WINBOOL = 0

	// ERROR_SUCCESS
	ERROR_SUCCESS = 0x00000000

	// CRYPT_E_NOT_FOUND — Cannot find object or property.
	CRYPT_E_NOT_FOUND = 0x80092004

	// NTE_BAD_ALGID — Invalid algorithm specified.
	NTE_BAD_ALGID = 0x80090008
)

// winAPIFlag specifies the flags that should be passed to
// CryptAcquireCertificatePrivateKey. This impacts whether the CryptoAPI or CNG
// API will be used.
//
// Possible values are:
//   0x00000000 —                                      — Only use CryptoAPI.
//   0x00010000 — CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG  — Prefer CryptoAPI.
//   0x00020000 — CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG — Prefer CNG.
//   0x00040000 — CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG   — Only uyse CNG.
var winAPIFlag C.DWORD = C.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG

// winStore is a wrapper around a C.HCERTSTORE.
type winStore struct {
	store C.HCERTSTORE
}

// openStore opens the current user's personal cert store.
func openStore(location StoreLocation) (*winStore, error) {
	storeName := unsafe.Pointer(stringToUTF16("MY"))
	defer C.free(storeName)

	var flags C.DWORD
	switch location {
	case User:
		flags |= C.CERT_SYSTEM_STORE_CURRENT_USER
	case System:
		flags |= C.CERT_SYSTEM_STORE_LOCAL_MACHINE | C.CERT_STORE_READONLY_FLAG
	}

	store := C.CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, storeName)
	if store == nil {
		return nil, lastError("failed to open system cert store")
	}

	return &winStore{store}, nil
}

// Identities implements the Store interface.
func (s *winStore) Identities() ([]Identity, error) {
	var (
		err    error
		idents = []Identity{}

		// CertFindChainInStore parameters
		encoding  = C.DWORD(C.X509_ASN_ENCODING)
		flags     = C.DWORD(C.CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG | C.CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG)
		findType  = C.DWORD(C.CERT_CHAIN_FIND_BY_ISSUER)
		params    = &C.CERT_CHAIN_FIND_BY_ISSUER_PARA{cbSize: C.DWORD(unsafe.Sizeof(C.CERT_CHAIN_FIND_BY_ISSUER_PARA{}))}
		paramsPtr = unsafe.Pointer(params)
		chainCtx  = C.PCCERT_CHAIN_CONTEXT(nil)
	)

	for {
		if chainCtx = C.CertFindChainInStore(s.store, encoding, flags, findType, paramsPtr, chainCtx); chainCtx == nil {
			break
		}
		if chainCtx.cChain < 1 {
			err = errors.New("bad chain")
			goto fail
		}

		// not sure why this isn't 1 << 29
		const maxPointerArray = 1 << 28

		// rgpChain is actually an array, but we only care about the first one.
		simpleChain := *chainCtx.rgpChain
		if simpleChain.cElement < 1 || simpleChain.cElement > maxPointerArray {
			err = errors.New("bad chain")
			goto fail
		}

		// Hacky way to get chain elements (c array) as a slice.
		chainElts := (*[maxPointerArray]C.PCERT_CHAIN_ELEMENT)(unsafe.Pointer(simpleChain.rgpElement))[:simpleChain.cElement:simpleChain.cElement]

		// Build chain of certificates from each elt's certificate context.
		chain := make([]C.PCCERT_CONTEXT, len(chainElts))
		for j := range chainElts {
			chain[j] = chainElts[j].pCertContext
		}

		idents = append(idents, newWinIdentity(chain))
	}

	if err = checkError("failed to iterate certs in store"); err != nil && errors.Cause(err) != errCode(CRYPT_E_NOT_FOUND) {
		goto fail
	}

	return idents, nil

fail:
	for _, ident := range idents {
		ident.Close()
	}

	return nil, err
}

// Import implements the Store interface.
func (s *winStore) Import(data []byte, password string) error {
	cdata := C.CBytes(data)
	defer C.free(cdata)

	cpw := stringToUTF16(password)
	defer C.free(unsafe.Pointer(cpw))

	pfx := &C.CRYPT_DATA_BLOB{
		cbData: C.DWORD(len(data)),
		pbData: (*C.BYTE)(cdata),
	}

	flags := C.CRYPT_USER_KEYSET

	// import into preferred KSP
	if winAPIFlag&C.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG > 0 {
		flags |= C.PKCS12_PREFER_CNG_KSP
	} else if winAPIFlag&C.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG > 0 {
		flags |= C.PKCS12_ALWAYS_CNG_KSP
	}

	store := C.PFXImportCertStore(pfx, cpw, C.DWORD(flags))
	if store == nil {
		return lastError("failed to import PFX cert store")
	}
	defer C.CertCloseStore(store, C.CERT_CLOSE_STORE_FORCE_FLAG)

	var (
		ctx      = C.PCCERT_CONTEXT(nil)
		encoding = C.DWORD(C.X509_ASN_ENCODING | C.PKCS_7_ASN_ENCODING)
	)

	for {
		// iterate through certs in temporary store
		if ctx = C.CertFindCertificateInStore(store, encoding, 0, C.CERT_FIND_ANY, nil, ctx); ctx == nil {
			if err := checkError("failed to iterate certs in store"); err != nil && errors.Cause(err) != errCode(CRYPT_E_NOT_FOUND) {
				return err
			}

			break
		}

		// Copy the cert to the system store.
		if ok := C.CertAddCertificateContextToStore(s.store, ctx, C.CERT_STORE_ADD_REPLACE_EXISTING, nil); ok == winFalse {
			return lastError("failed to add importerd certificate to MY store")
		}
	}

	return nil
}

// Close implements the Store interface.
func (s *winStore) Close() {
	C.CertCloseStore(s.store, 0)
	s.store = nil
}

// winIdentity implements the Identity interface.
type winIdentity struct {
	chain  []C.PCCERT_CONTEXT
	signer *winPrivateKey
}

func newWinIdentity(chain []C.PCCERT_CONTEXT) *winIdentity {
	for _, ctx := range chain {
		C.CertDuplicateCertificateContext(ctx)
	}

	return &winIdentity{chain: chain}
}

// Certificate implements the Identity interface.
func (i *winIdentity) Certificate() (*x509.Certificate, error) {
	return exportCertCtx(i.chain[0])
}

// CertificateChain implements the Identity interface.
func (i *winIdentity) CertificateChain() ([]*x509.Certificate, error) {
	var (
		certs = make([]*x509.Certificate, len(i.chain))
		err   error
	)

	for j := range i.chain {
		if certs[j], err = exportCertCtx(i.chain[j]); err != nil {
			return nil, err
		}
	}

	return certs, nil
}

// Signer implements the Identity interface.
func (i *winIdentity) Signer() (crypto.Signer, error) {
	return i.getPrivateKey()
}

// getPrivateKey gets this identity's private *winPrivateKey.
func (i *winIdentity) getPrivateKey() (*winPrivateKey, error) {
	if i.signer != nil {
		return i.signer, nil
	}

	cert, err := i.Certificate()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get identity certificate")
	}

	signer, err := newWinPrivateKey(i.chain[0], cert.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load identity private key")
	}

	i.signer = signer

	return i.signer, nil
}

// Delete implements the Identity interface.
func (i *winIdentity) Delete() error {
	// duplicate cert context, since CertDeleteCertificateFromStore will free it.
	deleteCtx := C.CertDuplicateCertificateContext(i.chain[0])

	// try deleting cert
	if ok := C.CertDeleteCertificateFromStore(deleteCtx); ok == winFalse {
		return lastError("failed to delete certificate from store")
	}

	// try deleting private key
	wpk, err := i.getPrivateKey()
	if err != nil {
		return errors.Wrap(err, "failed to get identity private key")
	}

	if err := wpk.Delete(); err != nil {
		return errors.Wrap(err, "failed to delete identity private key")
	}

	return nil
}

// Close implements the Identity interface.
func (i *winIdentity) Close() {
	if i.signer != nil {
		i.signer.Close()
		i.signer = nil
	}

	for _, ctx := range i.chain {
		C.CertFreeCertificateContext(ctx)
		i.chain = nil
	}
}

// winPrivateKey is a wrapper around a HCRYPTPROV_OR_NCRYPT_KEY_HANDLE.
type winPrivateKey struct {
	publicKey crypto.PublicKey

	// CryptoAPI fields
	capiProv C.HCRYPTPROV

	// CNG fields
	cngHandle C.NCRYPT_KEY_HANDLE
	keySpec   C.DWORD
}

// newWinPrivateKey gets a *winPrivateKey for the given certificate.
func newWinPrivateKey(certCtx C.PCCERT_CONTEXT, publicKey crypto.PublicKey) (*winPrivateKey, error) {
	var (
		provOrKey C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
		keySpec   C.DWORD
		mustFree  C.WINBOOL
	)

	if publicKey == nil {
		return nil, errors.New("nil public key")
	}

	// Get a handle for the found private key.
	if ok := C.CryptAcquireCertificatePrivateKey(certCtx, winAPIFlag, nil, &provOrKey, &keySpec, &mustFree); ok == winFalse {
		return nil, lastError("failed to get private key for certificate")
	}

	if mustFree != winTrue {
		// This shouldn't happen since we're not asking for cached keys.
		return nil, errors.New("CryptAcquireCertificatePrivateKey set mustFree")
	}

	if keySpec == C.CERT_NCRYPT_KEY_SPEC {
		return &winPrivateKey{
			publicKey: publicKey,
			cngHandle: C.NCRYPT_KEY_HANDLE(provOrKey),
			capiProv:  C.HCRYPTPROV(0),
		}, nil
	} else {
		return &winPrivateKey{
			publicKey: publicKey,
			capiProv:  C.HCRYPTPROV(provOrKey),
			keySpec:   keySpec,
		}, nil
	}
}

// Public implements the crypto.Signer interface.
func (wpk *winPrivateKey) Public() crypto.PublicKey {
	return wpk.publicKey
}

// Sign implements the crypto.Signer interface.
func (wpk *winPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if wpk.capiProv != 0 {
		return wpk.capiSignHash(opts, digest)
	} else if wpk.cngHandle != 0 {
		return wpk.cngSignHash(opts, digest)
	} else {
		return nil, errors.New("bad private key")
	}
}

// cngSignHash signs a digest using the CNG APIs.
func (wpk *winPrivateKey) cngSignHash(opts crypto.SignerOpts, digest []byte) ([]byte, error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	var (
		// input
		padPtr    = unsafe.Pointer(nil)
		digestPtr = (*C.BYTE)(&digest[0])
		digestLen = C.DWORD(len(digest))
		flags     = C.DWORD(0)

		// output
		sigLen = C.DWORD(0)
	)

	// setup pkcs1v1.5 padding for RSA
	if _, isRSA := wpk.publicKey.(*rsa.PublicKey); isRSA {
		var algId C.LPCWSTR
		switch hash {
		case crypto.SHA1:
			algId = BCRYPT_SHA1_ALGORITHM
		case crypto.SHA256:
			algId = BCRYPT_SHA256_ALGORITHM
		case crypto.SHA384:
			algId = BCRYPT_SHA384_ALGORITHM
		case crypto.SHA512:
			algId = BCRYPT_SHA512_ALGORITHM
		default:
			return nil, ErrUnsupportedHash
		}

		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			saltLen := pssOpts.SaltLength
			if saltLen < 0 {
				saltLen = len(digest)
			}
			padPtr = unsafe.Pointer(&C.BCRYPT_PSS_PADDING_INFO{
				pszAlgId: algId,
				cbSalt:   C.ULONG(saltLen),
			})
			flags |= C.BCRYPT_PAD_PSS
		} else {
			padPtr = unsafe.Pointer(&C.BCRYPT_PKCS1_PADDING_INFO{
				pszAlgId: algId,
			})
			flags |= C.BCRYPT_PAD_PKCS1
		}
	}

	// get signature length
	if err := checkStatus(C.NCryptSignHash(wpk.cngHandle, padPtr, digestPtr, digestLen, nil, 0, &sigLen, flags)); err != nil {
		return nil, errors.Wrap(err, "failed to get signature length")
	}

	// get signature
	sig := make([]byte, sigLen)
	sigPtr := (*C.BYTE)(&sig[0])
	if err := checkStatus(C.NCryptSignHash(wpk.cngHandle, padPtr, digestPtr, digestLen, sigPtr, sigLen, &sigLen, flags)); err != nil {
		return nil, errors.Wrap(err, "failed to sign digest")
	}

	// CNG returns a raw ECDSA signature, but we wan't ASN.1 DER encoding.
	if _, isEC := wpk.publicKey.(*ecdsa.PublicKey); isEC {
		if len(sig)%2 != 0 {
			return nil, errors.New("bad ecdsa signature from CNG")
		}

		type ecdsaSignature struct {
			R, S *big.Int
		}

		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])

		encoded, err := asn1.Marshal(ecdsaSignature{r, s})
		if err != nil {
			return nil, errors.Wrap(err, "failed to ASN.1 encode EC signature")
		}

		return encoded, nil
	}

	return sig, nil
}

// capiSignHash signs a digest using the CryptoAPI APIs.
func (wpk *winPrivateKey) capiSignHash(opts crypto.SignerOpts, digest []byte) ([]byte, error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	// Figure out which CryptoAPI hash algorithm we're using.
	var hash_alg C.ALG_ID

	switch hash {
	case crypto.SHA1:
		hash_alg = C.CALG_SHA1
	case crypto.SHA256:
		hash_alg = C.CALG_SHA_256
	case crypto.SHA384:
		hash_alg = C.CALG_SHA_384
	case crypto.SHA512:
		hash_alg = C.CALG_SHA_512
	default:
		return nil, ErrUnsupportedHash
	}

	// Instantiate a CryptoAPI hash object.
	var chash C.HCRYPTHASH

	if ok := C.CryptCreateHash(C.HCRYPTPROV(wpk.capiProv), hash_alg, 0, 0, &chash); ok == winFalse {
		if err := lastError("failed to create hash"); errors.Cause(err) == errCode(NTE_BAD_ALGID) {
			return nil, ErrUnsupportedHash
		} else {
			return nil, err
		}
	}
	defer C.CryptDestroyHash(chash)

	// Make sure the hash size matches.
	var (
		hashSize    C.DWORD
		hashSizePtr = (*C.BYTE)(unsafe.Pointer(&hashSize))
		hashSizeLen = C.DWORD(unsafe.Sizeof(hashSize))
	)

	if ok := C.CryptGetHashParam(chash, C.HP_HASHSIZE, hashSizePtr, &hashSizeLen, 0); ok == winFalse {
		return nil, lastError("failed to get hash size")
	}

	if hash.Size() != int(hashSize) {
		return nil, errors.New("invalid CryptoAPI hash")
	}

	// Put our digest into the hash object.
	digestPtr := (*C.BYTE)(unsafe.Pointer(&digest[0]))
	if ok := C.CryptSetHashParam(chash, C.HP_HASHVAL, digestPtr, 0); ok == winFalse {
		return nil, lastError("failed to set hash digest")
	}

	// Get signature length.
	var sigLen C.DWORD

	if ok := C.CryptSignHash(chash, wpk.keySpec, nil, 0, nil, &sigLen); ok == winFalse {
		return nil, lastError("failed to get signature length")
	}

	// Get signature
	var (
		sig    = make([]byte, int(sigLen))
		sigPtr = (*C.BYTE)(unsafe.Pointer(&sig[0]))
	)

	if ok := C.CryptSignHash(chash, wpk.keySpec, nil, 0, sigPtr, &sigLen); ok == winFalse {
		return nil, lastError("failed to sign digest")
	}

	// Signature is little endian, but we want big endian. Reverse it.
	for i := len(sig)/2 - 1; i >= 0; i-- {
		opp := len(sig) - 1 - i
		sig[i], sig[opp] = sig[opp], sig[i]
	}

	return sig, nil
}

func (wpk *winPrivateKey) Delete() error {
	if wpk.cngHandle != 0 {
		// Delete CNG key
		if err := checkStatus(C.NCryptDeleteKey(wpk.cngHandle, 0)); err != nil {
			return err
		}
	} else if wpk.capiProv != 0 {
		// Delete CryptoAPI key
		var (
			param unsafe.Pointer
			err   error

			containerName C.LPCTSTR
			providerName  C.LPCTSTR
			providerType  *C.DWORD
		)

		if param, err = wpk.getProviderParam(C.PP_CONTAINER); err != nil {
			return errors.Wrap(err, "failed to get PP_CONTAINER")
		} else {
			containerName = C.LPCTSTR(param)
		}

		if param, err = wpk.getProviderParam(C.PP_NAME); err != nil {
			return errors.Wrap(err, "failed to get PP_NAME")
		} else {
			providerName = C.LPCTSTR(param)
		}

		if param, err = wpk.getProviderParam(C.PP_PROVTYPE); err != nil {
			return errors.Wrap(err, "failed to get PP_PROVTYPE")
		} else {
			providerType = (*C.DWORD)(param)
		}

		// use CRYPT_SILENT too?
		var prov C.HCRYPTPROV
		if ok := C.CryptAcquireContext(&prov, containerName, providerName, *providerType, C.CRYPT_DELETEKEYSET); ok == winFalse {
			return lastError("failed to delete key set")
		}
	} else {
		return errors.New("bad private key")
	}

	return nil
}

// getProviderParam gets a parameter about a provider.
func (wpk *winPrivateKey) getProviderParam(param C.DWORD) (unsafe.Pointer, error) {
	var dataLen C.DWORD
	if ok := C.CryptGetProvParam(wpk.capiProv, param, nil, &dataLen, 0); ok == winFalse {
		return nil, lastError("failed to get provider parameter size")
	}

	data := make([]byte, dataLen)
	dataPtr := (*C.BYTE)(unsafe.Pointer(&data[0]))
	if ok := C.CryptGetProvParam(wpk.capiProv, param, dataPtr, &dataLen, 0); ok == winFalse {
		return nil, lastError("failed to get provider parameter")
	}

	// TODO leaking memory here
	return C.CBytes(data), nil
}

// Close closes this winPrivateKey.
func (wpk *winPrivateKey) Close() {
	if wpk.cngHandle != 0 {
		C.NCryptFreeObject(C.NCRYPT_HANDLE(wpk.cngHandle))
		wpk.cngHandle = 0
	}

	if wpk.capiProv != 0 {
		C.CryptReleaseContext(wpk.capiProv, 0)
		wpk.capiProv = 0
	}
}

// exportCertCtx exports a PCCERT_CONTEXT as an *x509.Certificate.
func exportCertCtx(ctx C.PCCERT_CONTEXT) (*x509.Certificate, error) {
	der := C.GoBytes(unsafe.Pointer(ctx.pbCertEncoded), C.int(ctx.cbCertEncoded))

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Wrap(err, "certificate parsing failed")
	}

	return cert, nil
}

type errCode uint64

// lastError gets the last error from the current thread. If there isn't one, it
// returns a new error.
func lastError(msg string) error {
	if err := checkError(msg); err != nil {
		return err
	}

	return errors.New(msg)
}

// checkError tries to get the last error from the current thread. If there
// isn't one, it returns nil.
func checkError(msg string) error {
	if code := errCode(C.GetLastError()); code != 0 {
		return errors.Wrap(code, msg)
	}

	return nil
}

func (c errCode) Error() string {
	cmsg := C.errMsg(C.DWORD(c))
	if cmsg == nil {
		return fmt.Sprintf("Error %X", int(c))
	}
	defer C.LocalFree(C.HLOCAL(cmsg))

	gomsg := C.GoString(cmsg)

	return fmt.Sprintf("Error: %X %s", int(c), gomsg)
}

type securityStatus uint64

func checkStatus(s C.SECURITY_STATUS) error {
	ss := securityStatus(s)

	if ss == ERROR_SUCCESS {
		return nil
	}

	if ss == NTE_BAD_ALGID {
		return ErrUnsupportedHash
	}

	return ss
}

func (ss securityStatus) Error() string {
	enc := make([]byte, 2, 10)
	copy(enc, "0x")
	h := strconv.AppendUint(enc, uint64(ss), 16)
	return fmt.Sprintf("SECURITY_STATUS %s", string(h))
}

func stringToUTF16(s string) C.LPCWSTR {
	// Not sure why this isn't 1 << 30...
	const maxUint16Array = 1 << 29

	if len(s) > maxUint16Array {
		panic("string too long")
	}

	wstr := utf16.Encode([]rune(s))

	p := C.calloc(C.size_t(len(wstr)+1), C.size_t(unsafe.Sizeof(uint16(0))))
	pp := (*[maxUint16Array]uint16)(p)
	copy(pp[:], wstr)

	return (C.LPCWSTR)(p)
}
