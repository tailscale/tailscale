// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tpm implements support for TPM 2.0 devices.
package tpm

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"tailscale.com/atomicfile"
	"tailscale.com/feature"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/paths"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

var infoOnce = sync.OnceValue(info)

func init() {
	feature.Register("tpm")
	hostinfo.RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
		hi.TPM = infoOnce()
	})
	store.Register(storePrefix, newStore)
}

func info() *tailcfg.TPMInfo {
	tpm, err := open()
	if err != nil {
		return nil
	}
	defer tpm.Close()

	info := new(tailcfg.TPMInfo)
	toStr := func(s *string) func(*tailcfg.TPMInfo, uint32) {
		return func(info *tailcfg.TPMInfo, value uint32) {
			*s += propToString(value)
		}
	}
	for _, cap := range []struct {
		prop  tpm2.TPMPT
		apply func(info *tailcfg.TPMInfo, value uint32)
	}{
		{tpm2.TPMPTManufacturer, toStr(&info.Manufacturer)},
		{tpm2.TPMPTVendorString1, toStr(&info.Vendor)},
		{tpm2.TPMPTVendorString2, toStr(&info.Vendor)},
		{tpm2.TPMPTVendorString3, toStr(&info.Vendor)},
		{tpm2.TPMPTVendorString4, toStr(&info.Vendor)},
		{tpm2.TPMPTRevision, func(info *tailcfg.TPMInfo, value uint32) { info.SpecRevision = int(value) }},
		{tpm2.TPMPTVendorTPMType, func(info *tailcfg.TPMInfo, value uint32) { info.Model = int(value) }},
		{tpm2.TPMPTFirmwareVersion1, func(info *tailcfg.TPMInfo, value uint32) { info.FirmwareVersion += uint64(value) << 32 }},
		{tpm2.TPMPTFirmwareVersion2, func(info *tailcfg.TPMInfo, value uint32) { info.FirmwareVersion += uint64(value) }},
	} {
		resp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(cap.prop),
			PropertyCount: 1,
		}.Execute(tpm)
		if err != nil {
			continue
		}
		props, err := resp.CapabilityData.Data.TPMProperties()
		if err != nil {
			continue
		}
		if len(props.TPMProperty) == 0 {
			continue
		}
		cap.apply(info, props.TPMProperty[0].Value)
	}
	return info
}

// propToString converts TPM_PT property value, which is a uint32, into a
// string of up to 4 ASCII characters. This encoding applies only to some
// properties, see
// https://trustedcomputinggroup.org/resource/tpm-library-specification/ Part
// 2, section 6.13.
func propToString(v uint32) string {
	chars := []byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
	// Delete any non-printable ASCII characters.
	return string(slices.DeleteFunc(chars, func(b byte) bool { return b < ' ' || b > '~' }))
}

const storePrefix = "tpmseal:"

func newStore(logf logger.Logf, path string) (ipn.StateStore, error) {
	path = strings.TrimPrefix(path, storePrefix)
	if err := paths.MkStateDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}
	var parsed map[ipn.StateKey][]byte
	bs, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to open %q: %w", path, err)
		}
		logf("tpm.newStore: initializing state file")
		// No state file, create a blank one.
		parsed = make(map[ipn.StateKey][]byte)
		initial := []byte("{}")
		sealed, err := seal(logf, initial)
		if err != nil {
			return nil, fmt.Errorf("failed to seal initial state file to TPM: %w", err)
		}
		if err := atomicfile.WriteFile(path, sealed, 0600); err != nil {
			return nil, fmt.Errorf("failed to write initial state file %q: %w", path, err)
		}
	} else {
		// State file exists, unseal and parse it.
		data, err := unseal(logf, bs)
		if err != nil {
			return nil, fmt.Errorf("failed to unseal state file: %w", err)
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse state file: %w", err)
		}
	}

	return &tpmStore{
		logf:  logf,
		path:  path,
		cache: parsed,
	}, nil
}

// tpmStore is an ipn.StateStore that stores the state in a file encrypted with
// a TPM-backed symmetric key.
//
// There's a bit of confusing encoding nesting here: file(json(tpm_seal(json(state)))).
// The outer-most JSON encoding is needed because sealing data with a TPM
// returns 2 blobs ("public" and "private") and we need both to unseal the
// data.
type tpmStore struct {
	logf logger.Logf
	path string

	mu    sync.RWMutex
	cache map[ipn.StateKey][]byte
}

func (s *tpmStore) ReadState(k ipn.StateKey) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.cache[k]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return bytes.Clone(v), nil
}

func (s *tpmStore) WriteState(k ipn.StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes.Equal(s.cache[k], bs) {
		return nil
	}
	s.cache[k] = bytes.Clone(bs)
	bs, err := json.Marshal(s.cache)
	if err != nil {
		return err
	}
	sealed, err := seal(s.logf, bs)
	if err != nil {
		return fmt.Errorf("failed to seal state file: %w", err)
	}
	return atomicfile.WriteFile(s.path, sealed, 0600)
}

type encryptedData struct {
	IV   []byte `json:"iv"`
	Data []byte `json:"data"`
}

// seal encrypts the data using the local TPM.
func seal(logf logger.Logf, data []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	enc, err := encryptDecrypt(logf, iv, data, false)
	if err != nil {
		return nil, err
	}

	res := encryptedData{
		IV:   iv,
		Data: enc,
	}
	return json.Marshal(res)
}

// unseal decrypts the data using the local TPM.
func unseal(logf logger.Logf, data []byte) ([]byte, error) {
	var enc encryptedData
	if err := json.Unmarshal(data, &enc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encryptedData: %w", err)
	}
	if len(enc.IV) == 0 || len(enc.Data) == 0 {
		return nil, errors.New("encryptedData is incomeplete")
	}

	out, err := encryptDecrypt(logf, enc.IV, enc.Data, true)
	return out, err
}

func encryptDecrypt(logf logger.Logf, iv, data []byte, decrypt bool) ([]byte, error) {
	tpm, err := open()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close()

	// Instantiate symmetric key.
	alg := tpm2.TPMAlgAES
	mode := tpm2.TPMAlgCFB
	createRes, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgSymCipher,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				UserWithAuth:        true,
				SensitiveDataOrigin: true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgSymCipher,
				&tpm2.TPMSSymCipherParms{
					Sym: tpm2.TPMTSymDefObject{
						Algorithm: alg,
						Mode:      tpm2.NewTPMUSymMode(alg, mode),
						KeyBits:   tpm2.NewTPMUSymKeyBits(alg, tpm2.TPMKeyBits(256)),
					},
				},
			),
		}),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2.CreatePrimary: %w", err)
	}
	defer func() {
		cmd := tpm2.FlushContext{FlushHandle: createRes.ObjectHandle}
		if _, err := cmd.Execute(tpm); err != nil {
			logf("tpm2.FlushContext: failed to flush key handle: %v", err)
		}
	}()
	kh := tpm2.AuthHandle{
		Handle: createRes.ObjectHandle,
		Name:   createRes.Name,
		Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 32),
	}

	// MAX_2B_BUFFER_SIZE is TPM-dependent but is required to be at least 1,024.
	const maxBufferSize = 1024

	// Encrypt/decrypt data in chunks.
	var out []byte
	for block, rest := []byte(nil), data; len(rest) > 0; {
		if len(rest) > maxBufferSize {
			block, rest = rest[:maxBufferSize], rest[maxBufferSize:]
		} else {
			block, rest = rest, nil
		}
		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: kh,
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    mode,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("tpm2.EncryptDecrypt2: %w", err)
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
}
