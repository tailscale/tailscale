package certstore

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"unsafe"
)

// work around https://golang.org/doc/go1.10#cgo
// in go>=1.10 CFTypeRefs are translated to uintptrs instead of pointers.
var (
	nilCFDictionaryRef   C.CFDictionaryRef
	nilSecCertificateRef C.SecCertificateRef
	nilCFArrayRef        C.CFArrayRef
	nilCFDataRef         C.CFDataRef
	nilCFErrorRef        C.CFErrorRef
	nilCFStringRef       C.CFStringRef
	nilSecIdentityRef    C.SecIdentityRef
	nilSecKeyRef         C.SecKeyRef
	nilCFAllocatorRef    C.CFAllocatorRef
)

// macStore is a bogus type. We have to explicitly open/close the store on
// windows, so we provide those methods here too.
type macStore int

// openStore is a function for opening a macStore.
func openStore(location StoreLocation) (macStore, error) {
	return macStore(0), nil
}

// Identities implements the Store interface.
func (s macStore) Identities() ([]Identity, error) {
	query := mapToCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):      C.CFTypeRef(C.kSecClassIdentity),
		C.CFTypeRef(C.kSecReturnRef):  C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit): C.CFTypeRef(C.kSecMatchLimitAll),
	})
	if query == nilCFDictionaryRef {
		return nil, errors.New("error creating CFDictionary")
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var absResult C.CFTypeRef
	if err := osStatusError(C.SecItemCopyMatching(query, &absResult)); err != nil {
		if err == errSecItemNotFound {
			return []Identity{}, nil
		}

		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(absResult))

	// don't need to release aryResult since the abstract result is released above.
	aryResult := C.CFArrayRef(absResult)

	// identRefs aren't owned by us initially. newMacIdentity retains them.
	n := C.CFArrayGetCount(aryResult)
	identRefs := make([]C.CFTypeRef, n)
	C.CFArrayGetValues(aryResult, C.CFRange{0, n}, (*unsafe.Pointer)(unsafe.Pointer(&identRefs[0])))

	idents := make([]Identity, 0, n)
	for _, identRef := range identRefs {
		idents = append(idents, newMacIdentity(C.SecIdentityRef(identRef)))
	}

	return idents, nil
}

// Import implements the Store interface.
func (s macStore) Import(data []byte, password string) error {
	cdata, err := bytesToCFData(data)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cdata))

	cpass := stringToCFString(password)
	defer C.CFRelease(C.CFTypeRef(cpass))

	cops := mapToCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecImportExportPassphrase): C.CFTypeRef(cpass),
	})
	if cops == nilCFDictionaryRef {
		return errors.New("error creating CFDictionary")
	}
	defer C.CFRelease(C.CFTypeRef(cops))

	var cret C.CFArrayRef
	if err := osStatusError(C.SecPKCS12Import(cdata, cops, &cret)); err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cret))

	return nil
}

// Close implements the Store interface.
func (s macStore) Close() {}

// macIdentity implements the Identity interface.
type macIdentity struct {
	ref   C.SecIdentityRef
	kref  C.SecKeyRef
	cref  C.SecCertificateRef
	crt   *x509.Certificate
	chain []*x509.Certificate
}

func newMacIdentity(ref C.SecIdentityRef) *macIdentity {
	C.CFRetain(C.CFTypeRef(ref))
	return &macIdentity{ref: ref}
}

// Certificate implements the Identity interface.
func (i *macIdentity) Certificate() (*x509.Certificate, error) {
	certRef, err := i.getCertRef()
	if err != nil {
		return nil, err
	}

	crt, err := exportCertRef(certRef)
	if err != nil {
		return nil, err
	}

	i.crt = crt

	return i.crt, nil
}

// CertificateChain implements the Identity interface.
func (i *macIdentity) CertificateChain() ([]*x509.Certificate, error) {
	if i.chain != nil {
		return i.chain, nil
	}

	certRef, err := i.getCertRef()
	if err != nil {
		return nil, err
	}

	policy := C.SecPolicyCreateSSL(0, nilCFStringRef)

	var trustRef C.SecTrustRef
	if err := osStatusError(C.SecTrustCreateWithCertificates(C.CFTypeRef(certRef), C.CFTypeRef(policy), &trustRef)); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(trustRef))

	var status C.SecTrustResultType
	if err := osStatusError(C.SecTrustEvaluate(trustRef, &status)); err != nil {
		return nil, err
	}

	var (
		nchain = C.SecTrustGetCertificateCount(trustRef)
		chain  = make([]*x509.Certificate, 0, int(nchain))
	)

	for i := C.CFIndex(0); i < nchain; i++ {
		// TODO: do we need to release these?
		chainCertref := C.SecTrustGetCertificateAtIndex(trustRef, i)
		if chainCertref == nilSecCertificateRef {
			return nil, errors.New("nil certificate in chain")
		}

		chainCert, err := exportCertRef(chainCertref)
		if err != nil {
			return nil, err
		}

		chain = append(chain, chainCert)
	}

	i.chain = chain

	return chain, nil
}

// Signer implements the Identity interface.
func (i *macIdentity) Signer() (crypto.Signer, error) {
	// pre-load the certificate so Public() is less likely to return nil
	// unexpectedly.
	if _, err := i.Certificate(); err != nil {
		return nil, err
	}

	return i, nil
}

// Delete implements the Identity interface.
func (i *macIdentity) Delete() error {
	itemList := []C.SecIdentityRef{i.ref}
	itemListPtr := (*unsafe.Pointer)(unsafe.Pointer(&itemList[0]))
	citemList := C.CFArrayCreate(nilCFAllocatorRef, itemListPtr, 1, nil)
	if citemList == nilCFArrayRef {
		return errors.New("error creating CFArray")
	}
	defer C.CFRelease(C.CFTypeRef(citemList))

	query := mapToCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):         C.CFTypeRef(C.kSecClassIdentity),
		C.CFTypeRef(C.kSecMatchItemList): C.CFTypeRef(citemList),
	})
	if query == nilCFDictionaryRef {
		return errors.New("error creating CFDictionary")
	}
	defer C.CFRelease(C.CFTypeRef(query))

	if err := osStatusError(C.SecItemDelete(query)); err != nil {
		return err
	}

	return nil
}

// Close implements the Identity interface.
func (i *macIdentity) Close() {
	if i.ref != nilSecIdentityRef {
		C.CFRelease(C.CFTypeRef(i.ref))
		i.ref = nilSecIdentityRef
	}

	if i.kref != nilSecKeyRef {
		C.CFRelease(C.CFTypeRef(i.kref))
		i.kref = nilSecKeyRef
	}

	if i.cref != nilSecCertificateRef {
		C.CFRelease(C.CFTypeRef(i.cref))
		i.cref = nilSecCertificateRef
	}
}

// Public implements the crypto.Signer interface.
func (i *macIdentity) Public() crypto.PublicKey {
	cert, err := i.Certificate()
	if err != nil {
		return nil
	}

	return cert.PublicKey
}

// Sign implements the crypto.Signer interface.
func (i *macIdentity) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()

	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	kref, err := i.getKeyRef()
	if err != nil {
		return nil, err
	}

	cdigest, err := bytesToCFData(digest)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cdigest))

	algo, err := i.getAlgo(opts)
	if err != nil {
		return nil, err
	}

	// sign the digest
	var cerr C.CFErrorRef
	csig := C.SecKeyCreateSignature(kref, algo, cdigest, &cerr)

	if err := cfErrorError(cerr); err != nil {
		defer C.CFRelease(C.CFTypeRef(cerr))

		return nil, err
	}

	if csig == nilCFDataRef {
		return nil, errors.New("nil signature from SecKeyCreateSignature")
	}

	defer C.CFRelease(C.CFTypeRef(csig))

	sig := cfDataToBytes(csig)

	return sig, nil
}

// getAlgo decides which algorithm to use with this key type for the given hash.
func (i *macIdentity) getAlgo(opts crypto.SignerOpts) (algo C.SecKeyAlgorithm, err error) {
	hash := opts.HashFunc()
	var crt *x509.Certificate
	if crt, err = i.Certificate(); err != nil {
		return
	}

	if _, ok := opts.(*rsa.PSSOptions); ok {
		switch hash {
		case crypto.SHA1:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPSSSHA1
		case crypto.SHA256:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256
		case crypto.SHA384:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPSSSHA384
		case crypto.SHA512:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPSSSHA512
		default:
			err = ErrUnsupportedHash
		}

		return
	}

	switch crt.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA1
		case crypto.SHA256:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
		case crypto.SHA384:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384
		case crypto.SHA512:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512
		default:
			err = ErrUnsupportedHash
		}
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
		case crypto.SHA256:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
		case crypto.SHA384:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
		case crypto.SHA512:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
		default:
			err = ErrUnsupportedHash
		}
	default:
		err = errors.New("unsupported key type")
	}

	return
}

// getKeyRef gets the SecKeyRef for this identity's pricate key.
func (i *macIdentity) getKeyRef() (C.SecKeyRef, error) {
	if i.kref != nilSecKeyRef {
		return i.kref, nil
	}

	var keyRef C.SecKeyRef
	if err := osStatusError(C.SecIdentityCopyPrivateKey(i.ref, &keyRef)); err != nil {
		return nilSecKeyRef, err
	}

	i.kref = keyRef

	return i.kref, nil
}

// getCertRef gets the SecCertificateRef for this identity's certificate.
func (i *macIdentity) getCertRef() (C.SecCertificateRef, error) {
	if i.cref != nilSecCertificateRef {
		return i.cref, nil
	}

	var certRef C.SecCertificateRef
	if err := osStatusError(C.SecIdentityCopyCertificate(i.ref, &certRef)); err != nil {
		return nilSecCertificateRef, err
	}

	i.cref = certRef

	return i.cref, nil
}

// exportCertRef gets a *x509.Certificate for the given SecCertificateRef.
func exportCertRef(certRef C.SecCertificateRef) (*x509.Certificate, error) {
	derRef := C.SecCertificateCopyData(certRef)
	if derRef == nilCFDataRef {
		return nil, errors.New("error getting certificate from identity")
	}
	defer C.CFRelease(C.CFTypeRef(derRef))

	der := cfDataToBytes(derRef)
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return crt, nil
}

// stringToCFString converts a Go string to a CFStringRef.
func stringToCFString(gostr string) C.CFStringRef {
	cstr := C.CString(gostr)
	defer C.free(unsafe.Pointer(cstr))

	return C.CFStringCreateWithCString(nilCFAllocatorRef, cstr, C.kCFStringEncodingUTF8)
}

// mapToCFDictionary converts a Go map[C.CFTypeRef]C.CFTypeRef to a
// CFDictionaryRef.
func mapToCFDictionary(gomap map[C.CFTypeRef]C.CFTypeRef) C.CFDictionaryRef {
	var (
		n      = len(gomap)
		keys   = make([]unsafe.Pointer, 0, n)
		values = make([]unsafe.Pointer, 0, n)
	)

	for k, v := range gomap {
		keys = append(keys, unsafe.Pointer(k))
		values = append(values, unsafe.Pointer(v))
	}

	return C.CFDictionaryCreate(nilCFAllocatorRef, &keys[0], &values[0], C.CFIndex(n), nil, nil)
}

// cfDataToBytes converts a CFDataRef to a Go byte slice.
func cfDataToBytes(cfdata C.CFDataRef) []byte {
	nBytes := C.CFDataGetLength(cfdata)
	bytesPtr := C.CFDataGetBytePtr(cfdata)
	return C.GoBytes(unsafe.Pointer(bytesPtr), C.int(nBytes))
}

// bytesToCFData converts a Go byte slice to a CFDataRef.
func bytesToCFData(gobytes []byte) (C.CFDataRef, error) {
	var (
		cptr = (*C.UInt8)(nil)
		clen = C.CFIndex(len(gobytes))
	)

	if len(gobytes) > 0 {
		cptr = (*C.UInt8)(&gobytes[0])
	}

	cdata := C.CFDataCreate(nilCFAllocatorRef, cptr, clen)
	if cdata == nilCFDataRef {
		return nilCFDataRef, errors.New("error creatin cfdata")
	}

	return cdata, nil
}

// osStatus wraps a C.OSStatus
type osStatus C.OSStatus

const (
	errSecItemNotFound = osStatus(C.errSecItemNotFound)
)

// osStatusError returns an error for an OSStatus unless it is errSecSuccess.
func osStatusError(s C.OSStatus) error {
	if s == C.errSecSuccess {
		return nil
	}

	return osStatus(s)
}

// Error implements the error interface.
func (s osStatus) Error() string {
	return fmt.Sprintf("OSStatus %d", s)
}

// cfErrorError returns an error for a CFErrorRef unless it is nil.
func cfErrorError(cerr C.CFErrorRef) error {
	if cerr == nilCFErrorRef {
		return nil
	}

	code := int(C.CFErrorGetCode(cerr))

	if cdescription := C.CFErrorCopyDescription(cerr); cdescription != nilCFStringRef {
		defer C.CFRelease(C.CFTypeRef(cdescription))

		if cstr := C.CFStringGetCStringPtr(cdescription, C.kCFStringEncodingUTF8); cstr != nil {
			str := C.GoString(cstr)

			return fmt.Errorf("CFError %d (%s)", code, str)
		}

	}

	return fmt.Errorf("CFError %d", code)
}
