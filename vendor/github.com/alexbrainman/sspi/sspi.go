// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package sspi

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// TODO: add documentation

type PackageInfo struct {
	Capabilities uint32
	Version      uint16
	RPCID        uint16
	MaxToken     uint32
	Name         string
	Comment      string
}

func QueryPackageInfo(pkgname string) (*PackageInfo, error) {
	name, err := syscall.UTF16PtrFromString(pkgname)
	if err != nil {
		return nil, err
	}
	var pi *SecPkgInfo
	ret := QuerySecurityPackageInfo(name, &pi)
	if ret != SEC_E_OK {
		return nil, ret
	}
	defer FreeContextBuffer((*byte)(unsafe.Pointer(pi)))

	return &PackageInfo{
		Capabilities: pi.Capabilities,
		Version:      pi.Version,
		RPCID:        pi.RPCID,
		MaxToken:     pi.MaxToken,
		Name:         syscall.UTF16ToString((*[2 << 12]uint16)(unsafe.Pointer(pi.Name))[:]),
		Comment:      syscall.UTF16ToString((*[2 << 12]uint16)(unsafe.Pointer(pi.Comment))[:]),
	}, nil
}

type Credentials struct {
	Handle CredHandle
	expiry syscall.Filetime
}

// AcquireCredentials calls the windows AcquireCredentialsHandle function and
// returns Credentials containing a security handle that can be used for
// InitializeSecurityContext or AcceptSecurityContext operations.
// As a special case, passing an empty string as the principal parameter will
// pass a null string to the underlying function.
func AcquireCredentials(principal string, pkgname string, creduse uint32, authdata *byte) (*Credentials, error) {
	var principalName *uint16
	if principal != "" {
		var err error
		principalName, err = syscall.UTF16PtrFromString(principal)
		if err != nil {
			return nil, err
		}
	}
	name, err := syscall.UTF16PtrFromString(pkgname)
	if err != nil {
		return nil, err
	}
	var c Credentials
	ret := AcquireCredentialsHandle(principalName, name, creduse, nil, authdata, 0, 0, &c.Handle, &c.expiry)
	if ret != SEC_E_OK {
		return nil, ret
	}
	return &c, nil
}

func (c *Credentials) Release() error {
	if c == nil {
		return nil
	}
	ret := FreeCredentialsHandle(&c.Handle)
	if ret != SEC_E_OK {
		return ret
	}
	return nil
}

func (c *Credentials) Expiry() time.Time {
	return time.Unix(0, c.expiry.Nanoseconds())
}

// TODO: add functions to display and manage RequestedFlags and EstablishedFlags fields.
// TODO: maybe get rid of RequestedFlags and EstablishedFlags fields, and replace them with input parameter for New...Context and return value of Update (instead of current bool parameter).

type updateFunc func(c *Context, targname *uint16, h, newh *CtxtHandle, out, in *SecBufferDesc) syscall.Errno

type Context struct {
	Cred             *Credentials
	Handle           *CtxtHandle
	handle           CtxtHandle
	updFn            updateFunc
	expiry           syscall.Filetime
	RequestedFlags   uint32
	EstablishedFlags uint32
}

func NewClientContext(cred *Credentials, flags uint32) *Context {
	return &Context{
		Cred:           cred,
		updFn:          initialize,
		RequestedFlags: flags,
	}
}

func NewServerContext(cred *Credentials, flags uint32) *Context {
	return &Context{
		Cred:           cred,
		updFn:          accept,
		RequestedFlags: flags,
	}
}

func initialize(c *Context, targname *uint16, h, newh *CtxtHandle, out, in *SecBufferDesc) syscall.Errno {
	return InitializeSecurityContext(&c.Cred.Handle, h, targname, c.RequestedFlags,
		0, SECURITY_NATIVE_DREP, in, 0, newh, out, &c.EstablishedFlags, &c.expiry)
}

func accept(c *Context, targname *uint16, h, newh *CtxtHandle, out, in *SecBufferDesc) syscall.Errno {
	return AcceptSecurityContext(&c.Cred.Handle, h, in, c.RequestedFlags,
		SECURITY_NATIVE_DREP, newh, out, &c.EstablishedFlags, &c.expiry)
}

func (c *Context) Update(targname *uint16, out, in *SecBufferDesc) syscall.Errno {
	h := c.Handle
	if c.Handle == nil {
		c.Handle = &c.handle
	}
	return c.updFn(c, targname, h, c.Handle, out, in)
}

func (c *Context) Release() error {
	if c == nil {
		return nil
	}
	ret := DeleteSecurityContext(c.Handle)
	if ret != SEC_E_OK {
		return ret
	}
	return nil
}

func (c *Context) Expiry() time.Time {
	return time.Unix(0, c.expiry.Nanoseconds())
}

// TODO: add comment to function doco that this "impersonation" is applied to current OS thread.
func (c *Context) ImpersonateUser() error {
	ret := ImpersonateSecurityContext(c.Handle)
	if ret != SEC_E_OK {
		return ret
	}
	return nil
}

func (c *Context) RevertToSelf() error {
	ret := RevertSecurityContext(c.Handle)
	if ret != SEC_E_OK {
		return ret
	}
	return nil
}

// Sizes queries the context for the sizes used in per-message functions.
// It returns the maximum token size used in authentication exchanges, the
// maximum signature size, the preferred integral size of messages, the
// size of any security trailer, and any error.
func (c *Context) Sizes() (uint32, uint32, uint32, uint32, error) {
	var s _SecPkgContext_Sizes
	ret := QueryContextAttributes(c.Handle, _SECPKG_ATTR_SIZES, (*byte)(unsafe.Pointer(&s)))
	if ret != SEC_E_OK {
		return 0, 0, 0, 0, ret
	}
	return s.MaxToken, s.MaxSignature, s.BlockSize, s.SecurityTrailer, nil
}

// VerifyFlags determines if all flags used to construct the context
// were honored (see NewClientContext).  It should be called after c.Update.
func (c *Context) VerifyFlags() error {
	return c.VerifySelectiveFlags(c.RequestedFlags)
}

// VerifySelectiveFlags determines if the given flags were honored (see NewClientContext).
// It should be called after c.Update.
func (c *Context) VerifySelectiveFlags(flags uint32) error {
	if valid, missing, extra := verifySelectiveFlags(flags, c.RequestedFlags); !valid {
		return fmt.Errorf("sspi: invalid flags check: desired=%b requested=%b missing=%b extra=%b", flags, c.RequestedFlags, missing, extra)
	}
	if valid, missing, extra := verifySelectiveFlags(flags, c.EstablishedFlags); !valid {
		return fmt.Errorf("sspi: invalid flags: desired=%b established=%b missing=%b extra=%b", flags, c.EstablishedFlags, missing, extra)
	}
	return nil
}

// verifySelectiveFlags determines if all bits requested in flags are set in establishedFlags.
// missing represents the bits set in flags that are not set in establishedFlags.
// extra represents the bits set in establishedFlags that are not set in flags.
// valid is true and missing is zero when establishedFlags has all of the requested flags.
func verifySelectiveFlags(flags, establishedFlags uint32) (valid bool, missing, extra uint32) {
	missing = flags&establishedFlags ^ flags
	extra = flags | establishedFlags ^ flags
	valid = missing == 0
	return valid, missing, extra
}

// NewSecBufferDesc returns an initialized SecBufferDesc describing the
// provided SecBuffer.
func NewSecBufferDesc(b []SecBuffer) *SecBufferDesc {
	return &SecBufferDesc{
		Version:      SECBUFFER_VERSION,
		BuffersCount: uint32(len(b)),
		Buffers:      &b[0],
	}
}
