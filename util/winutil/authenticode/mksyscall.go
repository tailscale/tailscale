// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package authenticode

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

//sys cryptCATAdminAcquireContext2(hCatAdmin *_HCATADMIN, pgSubsystem *windows.GUID, hashAlgorithm *uint16, strongHashPolicy *windows.CertStrongSignPara, flags uint32) (err error) [int32(failretval)==0] = wintrust.CryptCATAdminAcquireContext2
//sys cryptCATAdminCalcHashFromFileHandle2(hCatAdmin _HCATADMIN, file windows.Handle, pcbHash *uint32, pbHash *byte, flags uint32) (err error) [int32(failretval)==0] = wintrust.CryptCATAdminCalcHashFromFileHandle2
//sys cryptCATAdminCatalogInfoFromContext(hCatInfo _HCATINFO, catInfo *_CATALOG_INFO, flags uint32) (err error) [int32(failretval)==0] = wintrust.CryptCATCatalogInfoFromContext
//sys cryptCATAdminEnumCatalogFromHash(hCatAdmin _HCATADMIN, pbHash *byte, cbHash uint32, flags uint32, prevCatInfo *_HCATINFO) (ret _HCATINFO, err error) [ret==0] = wintrust.CryptCATAdminEnumCatalogFromHash
//sys cryptCATAdminReleaseCatalogContext(hCatAdmin _HCATADMIN, hCatInfo _HCATINFO, flags uint32) (err error) [int32(failretval)==0] = wintrust.CryptCATAdminReleaseCatalogContext
//sys cryptCATAdminReleaseContext(hCatAdmin _HCATADMIN, flags uint32) (err error) [int32(failretval)==0] = wintrust.CryptCATAdminReleaseContext
//sys cryptMsgClose(cryptMsg windows.Handle) (err error) [int32(failretval)==0] = crypt32.CryptMsgClose
//sys cryptMsgGetParam(cryptMsg windows.Handle, paramType uint32, index uint32, data unsafe.Pointer, dataLen *uint32) (err error) [int32(failretval)==0] = crypt32.CryptMsgGetParam
//sys cryptVerifyMessageSignature(pVerifyPara *_CRYPT_VERIFY_MESSAGE_PARA, signerIndex uint32, pbSignedBlob *byte, cbSignedBlob uint32, pbDecoded *byte, pdbDecoded *uint32, ppSignerCert **windows.CertContext) (err error) [int32(failretval)==0] = crypt32.CryptVerifyMessageSignature
//sys msiGetFileSignatureInformation(signedObjectPath *uint16, flags uint32, certCtx **windows.CertContext, pbHashData *byte, cbHashData *uint32) (ret wingoes.HRESULT) = msi.MsiGetFileSignatureInformationW
