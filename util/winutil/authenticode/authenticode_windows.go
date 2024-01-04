// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package authenticode

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/dblohm7/wingoes"
	"github.com/dblohm7/wingoes/pe"
	"golang.org/x/sys/windows"
)

var (
	// ErrSigNotFound is returned if no authenticode signature could be found.
	ErrSigNotFound = errors.New("authenticode signature not found")
	// ErrUnexpectedCertSubject is wrapped with the actual cert subject and
	// returned when the binary is signed by a different subject than expected.
	ErrUnexpectedCertSubject        = errors.New("unexpected cert subject")
	errCertSubjectNotFound          = errors.New("cert subject not found")
	errCertSubjectDecodeLenMismatch = errors.New("length mismatch while decoding cert subject")
)

const (
	_CERT_STRONG_SIGN_OID_INFO_CHOICE = 2
	_CMSG_SIGNER_CERT_INFO_PARAM      = 7
	_MSI_INVALID_HASH_IS_FATAL        = 1
	_TRUST_E_NOSIGNATURE              = wingoes.HRESULT(-((0x800B0100 ^ 0xFFFFFFFF) + 1))
)

// Verify performs authenticode verification on the file at path, and also
// ensures that expectedCertSubject matches the actual cert subject. path may
// point to either a PE binary or an MSI package. ErrSigNotFound is returned if
// no signature is found.
func Verify(path string, expectedCertSubject string) error {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	var subject string
	if strings.EqualFold(filepath.Ext(path), ".msi") {
		subject, err = verifyMSI(path16)
	} else {
		subject, _, err = queryPE(path16, true)
	}

	if err != nil {
		return err
	}

	if subject != expectedCertSubject {
		return fmt.Errorf("%w %q", ErrUnexpectedCertSubject, subject)
	}

	return nil
}

// SigProvenance indicates whether an authenticode signature was embedded within
// the file itself, or the signature applies to an associated catalog file.
type SigProvenance int

const (
	SigProvUnknown = SigProvenance(iota)
	SigProvEmbedded
	SigProvCatalog
)

// QueryCertSubject obtains the subject associated with the certificate used to
// sign the PE binary located at path. When err == nil, it also returns the
// provenance of that signature. ErrSigNotFound is returned if no signature
// is found. Note that this function does *not* validate the chain of trust; use
// Verify for that purpose!
func QueryCertSubject(path string) (certSubject string, provenance SigProvenance, err error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", SigProvUnknown, err
	}

	return queryPE(path16, false)
}

func queryPE(utf16Path *uint16, verify bool) (string, SigProvenance, error) {
	certSubject, err := queryEmbeddedCertSubject(utf16Path, verify)

	switch {
	case err == ErrSigNotFound:
		// Try looking for the signature in a catalog file.
	default:
		return certSubject, SigProvEmbedded, err
	}

	certSubject, err = queryCatalogCertSubject(utf16Path, verify)
	switch {
	case err == ErrSigNotFound:
		return "", SigProvUnknown, err
	default:
		return certSubject, SigProvCatalog, err
	}
}

// CertSubjectError is returned if a cert subject was successfully resolved but
// there was a problem encountered during its extraction. The Subject is
// provided for informational purposes but is not presumed to be accurate.
type CertSubjectError struct {
	Err     error  // The error that occurred while extracting the cert subject.
	Subject string // The (possibly invalid) cert subject that was extracted.
}

func (e *CertSubjectError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Subject == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("cert subject %q: %v", e.Subject, e.Err)
}

func (e *CertSubjectError) Unwrap() error {
	return e.Err
}

func verifyMSI(path *uint16) (string, error) {
	var certCtx *windows.CertContext
	hr := msiGetFileSignatureInformation(path, _MSI_INVALID_HASH_IS_FATAL, &certCtx, nil, nil)
	if e := wingoes.ErrorFromHRESULT(hr); e.Failed() {
		if e == wingoes.ErrorFromHRESULT(_TRUST_E_NOSIGNATURE) {
			return "", ErrSigNotFound
		}
		return "", e
	}
	defer windows.CertFreeCertificateContext(certCtx)

	return certSubjectFromCertContext(certCtx)
}

func certSubjectFromCertContext(certCtx *windows.CertContext) (string, error) {
	desiredLen := windows.CertGetNameString(
		certCtx,
		windows.CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		nil,
		nil,
		0,
	)
	if desiredLen <= 1 {
		return "", errCertSubjectNotFound
	}

	buf := make([]uint16, desiredLen)
	actualLen := windows.CertGetNameString(
		certCtx,
		windows.CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		nil,
		&buf[0],
		desiredLen,
	)
	if actualLen != desiredLen {
		return "", errCertSubjectDecodeLenMismatch
	}

	return windows.UTF16ToString(buf), nil
}

type objectQuery struct {
	certStore    windows.Handle
	cryptMsg     windows.Handle
	encodingType uint32
}

func newObjectQuery(utf16Path *uint16) (*objectQuery, error) {
	var oq objectQuery
	if err := windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(utf16Path),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&oq.encodingType,
		nil,
		nil,
		&oq.certStore,
		&oq.cryptMsg,
		nil,
	); err != nil {
		return nil, err
	}

	return &oq, nil
}

func (oq *objectQuery) Close() error {
	if oq.certStore != 0 {
		if err := windows.CertCloseStore(oq.certStore, 0); err != nil {
			return err
		}
		oq.certStore = 0
	}

	if oq.cryptMsg != 0 {
		if err := cryptMsgClose(oq.cryptMsg); err != nil {
			return err
		}
		oq.cryptMsg = 0
	}

	return nil
}

func (oq *objectQuery) certSubject() (string, error) {
	var certInfoLen uint32
	if err := cryptMsgGetParam(
		oq.cryptMsg,
		_CMSG_SIGNER_CERT_INFO_PARAM,
		0,
		unsafe.Pointer(nil),
		&certInfoLen,
	); err != nil {
		return "", err
	}

	buf := make([]byte, certInfoLen)
	if err := cryptMsgGetParam(
		oq.cryptMsg,
		_CMSG_SIGNER_CERT_INFO_PARAM,
		0,
		unsafe.Pointer(&buf[0]),
		&certInfoLen,
	); err != nil {
		return "", err
	}

	certInfo := (*windows.CertInfo)(unsafe.Pointer(&buf[0]))
	certCtx, err := windows.CertFindCertificateInStore(
		oq.certStore,
		oq.encodingType,
		0,
		windows.CERT_FIND_SUBJECT_CERT,
		unsafe.Pointer(certInfo),
		nil,
	)
	if err != nil {
		return "", err
	}
	defer windows.CertFreeCertificateContext(certCtx)

	return certSubjectFromCertContext(certCtx)
}

func extractCertBlob(hfile windows.Handle) ([]byte, error) {
	pef, err := pe.NewPEFromFileHandle(hfile)
	if err != nil {
		return nil, err
	}
	defer pef.Close()

	certsAny, err := pef.DataDirectoryEntry(pe.IMAGE_DIRECTORY_ENTRY_SECURITY)
	if err != nil {
		if errors.Is(err, pe.ErrNotPresent) {
			err = ErrSigNotFound
		}
		return nil, err
	}

	certs, ok := certsAny.([]pe.AuthenticodeCert)
	if !ok || len(certs) == 0 {
		return nil, ErrSigNotFound
	}

	for _, cert := range certs {
		if cert.Revision() != pe.WIN_CERT_REVISION_2_0 || cert.Type() != pe.WIN_CERT_TYPE_PKCS_SIGNED_DATA {
			continue
		}
		return cert.Data(), nil
	}

	return nil, ErrSigNotFound
}

type _HCRYPTPROV windows.Handle

type _CRYPT_VERIFY_MESSAGE_PARA struct {
	CBSize                 uint32
	MsgAndCertEncodingType uint32
	HCryptProv             _HCRYPTPROV
	FNGetSignerCertificate uintptr
	GetArg                 uintptr
	StrongSignPara         *windows.CertStrongSignPara
}

func querySubjectFromBlob(blob []byte) (string, error) {
	para := _CRYPT_VERIFY_MESSAGE_PARA{
		CBSize:                 uint32(unsafe.Sizeof(_CRYPT_VERIFY_MESSAGE_PARA{})),
		MsgAndCertEncodingType: windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING,
	}

	var certCtx *windows.CertContext
	if err := cryptVerifyMessageSignature(&para, 0, &blob[0], uint32(len(blob)), nil, nil, &certCtx); err != nil {
		return "", err
	}
	defer windows.CertFreeCertificateContext(certCtx)

	return certSubjectFromCertContext(certCtx)
}

func queryEmbeddedCertSubject(utf16Path *uint16, verify bool) (string, error) {
	peBinary, err := windows.CreateFile(
		utf16Path,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(peBinary)

	blob, err := extractCertBlob(peBinary)
	if err != nil {
		return "", err
	}

	certSubj, err := querySubjectFromBlob(blob)
	if err != nil {
		return "", err
	}

	if !verify {
		return certSubj, nil
	}

	wintrustArg := unsafe.Pointer(&windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: utf16Path,
		File:     peBinary,
	})
	if err := verifyTrust(windows.WTD_CHOICE_FILE, wintrustArg); err != nil {
		// We might still want to know who the cert subject claims to be
		// even if the validation has failed (eg for troubleshooting purposes),
		// so we return a CertSubjectError.
		return "", &CertSubjectError{Err: err, Subject: certSubj}
	}

	return certSubj, nil
}

var (
	_BCRYPT_SHA256_ALGORITHM   = &([]uint16{'S', 'H', 'A', '2', '5', '6', 0})[0]
	_OID_CERT_STRONG_SIGN_OS_1 = &([]byte("1.3.6.1.4.1.311.72.1.1\x00"))[0]
)

type _HCATADMIN windows.Handle
type _HCATINFO windows.Handle

type _CATALOG_INFO struct {
	size        uint32
	catalogFile [windows.MAX_PATH]uint16
}

type _WINTRUST_CATALOG_INFO struct {
	size                 uint32
	catalogVersion       uint32
	catalogFilePath      *uint16
	memberTag            *uint16
	memberFilePath       *uint16
	memberFile           windows.Handle
	pCalculatedFileHash  *byte
	cbCalculatedFileHash uint32
	catalogContext       uintptr
	catAdmin             _HCATADMIN
}

func queryCatalogCertSubject(utf16Path *uint16, verify bool) (string, error) {
	var catAdmin _HCATADMIN
	policy := windows.CertStrongSignPara{
		Size:                      uint32(unsafe.Sizeof(windows.CertStrongSignPara{})),
		InfoChoice:                _CERT_STRONG_SIGN_OID_INFO_CHOICE,
		InfoOrSerializedInfoOrOID: unsafe.Pointer(_OID_CERT_STRONG_SIGN_OS_1),
	}
	if err := cryptCATAdminAcquireContext2(
		&catAdmin,
		nil,
		_BCRYPT_SHA256_ALGORITHM,
		&policy,
		0,
	); err != nil {
		return "", err
	}
	defer cryptCATAdminReleaseContext(catAdmin, 0)

	// We use windows.CreateFile instead of standard library facilities because:
	// 1. Subsequent API calls directly utilize the file's Win32 HANDLE;
	// 2. We're going to be hashing the contents of this file, so we want to
	//    provide a sequential-scan hint to the kernel.
	memberFile, err := windows.CreateFile(
		utf16Path,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(memberFile)

	var hashLen uint32
	if err := cryptCATAdminCalcHashFromFileHandle2(
		catAdmin,
		memberFile,
		&hashLen,
		nil,
		0,
	); err != nil {
		return "", err
	}

	hashBuf := make([]byte, hashLen)
	if err := cryptCATAdminCalcHashFromFileHandle2(
		catAdmin,
		memberFile,
		&hashLen,
		&hashBuf[0],
		0,
	); err != nil {
		return "", err
	}

	catInfoCtx, err := cryptCATAdminEnumCatalogFromHash(
		catAdmin,
		&hashBuf[0],
		hashLen,
		0,
		nil,
	)
	if err != nil {
		if err == windows.ERROR_NOT_FOUND {
			err = ErrSigNotFound
		}
		return "", err
	}
	defer cryptCATAdminReleaseCatalogContext(catAdmin, catInfoCtx, 0)

	catInfo := _CATALOG_INFO{
		size: uint32(unsafe.Sizeof(_CATALOG_INFO{})),
	}
	if err := cryptCATAdminCatalogInfoFromContext(catInfoCtx, &catInfo, 0); err != nil {
		return "", err
	}

	oq, err := newObjectQuery(&catInfo.catalogFile[0])
	if err != nil {
		return "", err
	}
	defer oq.Close()

	certSubj, err := oq.certSubject()
	if err != nil {
		return "", err
	}

	if !verify {
		return certSubj, nil
	}

	// memberTag is required to be formatted this way.
	hbh := strings.ToUpper(hex.EncodeToString(hashBuf))
	memberTag, err := windows.UTF16PtrFromString(hbh)
	if err != nil {
		return "", err
	}

	wintrustArg := unsafe.Pointer(&_WINTRUST_CATALOG_INFO{
		size:            uint32(unsafe.Sizeof(_WINTRUST_CATALOG_INFO{})),
		catalogFilePath: &catInfo.catalogFile[0],
		memberTag:       memberTag,
		memberFilePath:  utf16Path,
		memberFile:      memberFile,
		catAdmin:        catAdmin,
	})
	if err := verifyTrust(windows.WTD_CHOICE_CATALOG, wintrustArg); err != nil {
		// We might still want to know who the cert subject claims to be
		// even if the validation has failed (eg for troubleshooting purposes),
		// so we return a CertSubjectError.
		return "", &CertSubjectError{Err: err, Subject: certSubj}
	}

	return certSubj, nil
}

func verifyTrust(infoType uint32, info unsafe.Pointer) error {
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_WHOLECHAIN, // Full revocation checking, as this is called with network connectivity.
		UnionChoice:                     infoType,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: info,
	}
	err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)

	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)

	return err
}
