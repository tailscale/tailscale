// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package common

import (
	"errors"
	"syscall"

	"github.com/alexbrainman/sspi"
)

func BuildAuthIdentity(domain, username, password string) (*sspi.SEC_WINNT_AUTH_IDENTITY, error) {
	if len(username) == 0 {
		return nil, errors.New("username parameter cannot be empty")
	}
	d, err := syscall.UTF16FromString(domain)
	if err != nil {
		return nil, err
	}
	u, err := syscall.UTF16FromString(username)
	if err != nil {
		return nil, err
	}
	p, err := syscall.UTF16FromString(password)
	if err != nil {
		return nil, err
	}
	return &sspi.SEC_WINNT_AUTH_IDENTITY{
		User:           &u[0],
		UserLength:     uint32(len(u) - 1), // do not count terminating 0
		Domain:         &d[0],
		DomainLength:   uint32(len(d) - 1), // do not count terminating 0
		Password:       &p[0],
		PasswordLength: uint32(len(p) - 1), // do not count terminating 0
		Flags:          sspi.SEC_WINNT_AUTH_IDENTITY_UNICODE,
	}, nil
}

func UpdateContext(c *sspi.Context, dst, src []byte, targetName *uint16) (authCompleted bool, n int, err error) {
	var inBuf, outBuf [1]sspi.SecBuffer
	inBuf[0].Set(sspi.SECBUFFER_TOKEN, src)
	inBufs := &sspi.SecBufferDesc{
		Version:      sspi.SECBUFFER_VERSION,
		BuffersCount: 1,
		Buffers:      &inBuf[0],
	}
	outBuf[0].Set(sspi.SECBUFFER_TOKEN, dst)
	outBufs := &sspi.SecBufferDesc{
		Version:      sspi.SECBUFFER_VERSION,
		BuffersCount: 1,
		Buffers:      &outBuf[0],
	}
	ret := c.Update(targetName, outBufs, inBufs)
	switch ret {
	case sspi.SEC_E_OK:
		// session established -> return success
		return true, int(outBuf[0].BufferSize), nil
	case sspi.SEC_I_COMPLETE_NEEDED, sspi.SEC_I_COMPLETE_AND_CONTINUE:
		ret = sspi.CompleteAuthToken(c.Handle, outBufs)
		if ret != sspi.SEC_E_OK {
			return false, 0, ret
		}
	case sspi.SEC_I_CONTINUE_NEEDED:
	default:
		return false, 0, ret
	}
	return false, int(outBuf[0].BufferSize), nil
}

func MakeSignature(c *sspi.Context, msg []byte, qop, seqno uint32) ([]byte, error) {
	_, maxSignature, _, _, err := c.Sizes()
	if err != nil {
		return nil, err
	}

	if maxSignature == 0 {
		return nil, errors.New("integrity services are not requested or unavailable")
	}

	var b [2]sspi.SecBuffer
	b[0].Set(sspi.SECBUFFER_DATA, msg)
	b[1].Set(sspi.SECBUFFER_TOKEN, make([]byte, maxSignature))

	ret := sspi.MakeSignature(c.Handle, qop, sspi.NewSecBufferDesc(b[:]), seqno)
	if ret != sspi.SEC_E_OK {
		return nil, ret
	}

	return b[1].Bytes(), nil
}

func EncryptMessage(c *sspi.Context, msg []byte, qop, seqno uint32) ([]byte, error) {
	_ /*maxToken*/, maxSignature, cBlockSize, cSecurityTrailer, err := c.Sizes()
	if err != nil {
		return nil, err
	}

	if maxSignature == 0 {
		return nil, errors.New("integrity services are not requested or unavailable")
	}

	var b [3]sspi.SecBuffer
	b[0].Set(sspi.SECBUFFER_TOKEN, make([]byte, cSecurityTrailer))
	b[1].Set(sspi.SECBUFFER_DATA, msg)
	b[2].Set(sspi.SECBUFFER_PADDING, make([]byte, cBlockSize))

	ret := sspi.EncryptMessage(c.Handle, qop, sspi.NewSecBufferDesc(b[:]), seqno)
	if ret != sspi.SEC_E_OK {
		return nil, ret
	}

	r0, r1, r2 := b[0].Bytes(), b[1].Bytes(), b[2].Bytes()
	res := make([]byte, 0, len(r0)+len(r1)+len(r2))
	res = append(res, r0...)
	res = append(res, r1...)
	res = append(res, r2...)

	return res, nil
}

func DecryptMessage(c *sspi.Context, msg []byte, seqno uint32) (uint32, []byte, error) {
	var b [2]sspi.SecBuffer
	b[0].Set(sspi.SECBUFFER_STREAM, msg)
	b[1].Set(sspi.SECBUFFER_DATA, []byte{})

	var qop uint32
	ret := sspi.DecryptMessage(c.Handle, sspi.NewSecBufferDesc(b[:]), seqno, &qop)
	if ret != sspi.SEC_E_OK {
		return qop, nil, ret
	}

	return qop, b[1].Bytes(), nil
}

func VerifySignature(c *sspi.Context, msg, token []byte, seqno uint32) (uint32, error) {
	var b [2]sspi.SecBuffer
	b[0].Set(sspi.SECBUFFER_DATA, msg)
	b[1].Set(sspi.SECBUFFER_TOKEN, token)

	var qop uint32

	ret := sspi.VerifySignature(c.Handle, sspi.NewSecBufferDesc(b[:]), seqno, &qop)
	if ret != sspi.SEC_E_OK {
		return 0, ret
	}

	return qop, nil
}
