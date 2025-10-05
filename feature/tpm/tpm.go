// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tpm implements support for TPM 2.0 devices.
package tpm

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/nacl/secretbox"
	"tailscale.com/atomicfile"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/paths"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/testenv"
)

var infoOnce = sync.OnceValue(info)

func init() {
	feature.Register("tpm")
	feature.HookTPMAvailable.Set(tpmSupported)
	feature.HookHardwareAttestationAvailable.Set(tpmSupported)

	hostinfo.RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
		hi.TPM = infoOnce()
	})
	store.Register(store.TPMPrefix, newStore)
	if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		key.RegisterHardwareAttestationKeyFns(
			func() key.HardwareAttestationKey { return &attestationKey{} },
			func() (key.HardwareAttestationKey, error) { return newAttestationKey() },
		)
	}
}

func tpmSupported() bool {
	tpm, err := open()
	if err != nil {
		return false
	}
	tpm.Close()
	return true
}

var verboseTPM = envknob.RegisterBool("TS_DEBUG_TPM")

func info() *tailcfg.TPMInfo {
	logf := logger.Discard
	if !testenv.InTest() || verboseTPM() {
		logf = log.New(log.Default().Writer(), "TPM: ", 0).Printf
	}

	tpm, err := open()
	if err != nil {
		if !os.IsNotExist(err) || verboseTPM() {
			// Only log if it's an interesting error, not just "no TPM",
			// as is very common, especially in VMs.
			logf("error opening: %v", err)
		}
		return nil
	}
	if verboseTPM() {
		logf("successfully opened")
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
			logf("GetCapability %v: %v", cap.prop, err)
			continue
		}
		props, err := resp.CapabilityData.Data.TPMProperties()
		if err != nil {
			logf("GetCapability %v: %v", cap.prop, err)
			continue
		}
		if len(props.TPMProperty) == 0 {
			continue
		}
		cap.apply(info, props.TPMProperty[0].Value)
	}
	logf("successfully read all properties")
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

func newStore(logf logger.Logf, path string) (ipn.StateStore, error) {
	path = strings.TrimPrefix(path, store.TPMPrefix)
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

		var key [32]byte
		// crypto/rand.Read never returns an error.
		rand.Read(key[:])

		store := &tpmStore{
			logf:  logf,
			path:  path,
			key:   key,
			cache: make(map[ipn.StateKey][]byte),
		}
		if err := store.writeSealed(); err != nil {
			return nil, fmt.Errorf("failed to write initial state file: %w", err)
		}
		return store, nil
	}

	// State file exists, unseal and parse it.
	var sealed encryptedData
	if err := json.Unmarshal(bs, &sealed); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state file: %w", err)
	}
	if len(sealed.Data) == 0 || sealed.Key == nil || len(sealed.Nonce) == 0 {
		return nil, fmt.Errorf("state file %q has not been TPM-sealed or is corrupt", path)
	}
	data, err := unseal(logf, sealed)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal state file: %w", err)
	}
	if err := json.Unmarshal(data.Data, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse state file: %w", err)
	}
	return &tpmStore{
		logf:  logf,
		path:  path,
		key:   data.Key,
		cache: parsed,
	}, nil
}

// tpmStore is an ipn.StateStore that stores the state in a secretbox-encrypted
// file using a TPM-sealed symmetric key.
type tpmStore struct {
	ipn.EncryptedStateStore

	logf logger.Logf
	path string
	key  [32]byte

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

	return s.writeSealed()
}

func (s *tpmStore) writeSealed() error {
	bs, err := json.Marshal(s.cache)
	if err != nil {
		return err
	}
	sealed, err := seal(s.logf, decryptedData{Key: s.key, Data: bs})
	if err != nil {
		return fmt.Errorf("failed to seal state file: %w", err)
	}
	buf, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(s.path, buf, 0600)
}

func (s *tpmStore) All() iter.Seq2[ipn.StateKey, []byte] {
	return func(yield func(ipn.StateKey, []byte) bool) {
		s.mu.Lock()
		defer s.mu.Unlock()

		for k, v := range s.cache {
			if !yield(k, v) {
				break
			}
		}
	}
}

// Ensure tpmStore implements store.ExportableStore for migration to/from
// store.FileStore.
var _ store.ExportableStore = (*tpmStore)(nil)

// The nested levels of encoding and encryption are confusing, so here's what's
// going on in plain English.
//
// Not all TPM devices support symmetric encryption (TPM2_EncryptDecrypt2)
// natively, but they do support "sealing" small values (see
// tpmSeal/tpmUnseal). The size limit is too small for the actual state file,
// so we seal a symmetric key instead. This symmetric key is then used to seal
// the actual data using nacl/secretbox.
// Confusingly, both TPMs and secretbox use "seal" terminology.
//
// tpmSeal/tpmUnseal do the lower-level sealing of small []byte blobs, which we
// use to seal a 32-byte secretbox key.
//
// seal/unseal do the higher-level sealing of store data using secretbox, and
// also sealing of the symmetric key using TPM.

// decryptedData contains the fully decrypted raw data along with the symmetric
// key used for secretbox. This struct should only live in memory and never get
// stored to disk!
type decryptedData struct {
	Key  [32]byte
	Data []byte
}

func (decryptedData) MarshalJSON() ([]byte, error) {
	return nil, errors.New("[unexpected]: decryptedData should never get JSON-marshaled!")
}

// encryptedData contains the secretbox-sealed data and nonce, along with a
// TPM-sealed key. All fields are required.
type encryptedData struct {
	Key   *tpmSealedData `json:"key"`
	Nonce []byte         `json:"nonce"`
	Data  []byte         `json:"data"`
}

func seal(logf logger.Logf, dec decryptedData) (*encryptedData, error) {
	var nonce [24]byte
	// crypto/rand.Read never returns an error.
	rand.Read(nonce[:])

	sealedData := secretbox.Seal(nil, dec.Data, &nonce, &dec.Key)
	sealedKey, err := tpmSeal(logf, dec.Key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to seal encryption key to TPM: %w", err)
	}

	return &encryptedData{
		Key:   sealedKey,
		Nonce: nonce[:],
		Data:  sealedData,
	}, nil
}

func unseal(logf logger.Logf, data encryptedData) (*decryptedData, error) {
	if len(data.Nonce) != 24 {
		return nil, fmt.Errorf("nonce should be 24 bytes long, got %d", len(data.Nonce))
	}

	unsealedKey, err := tpmUnseal(logf, data.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal encryption key with TPM: %w", err)
	}
	if len(unsealedKey) != 32 {
		return nil, fmt.Errorf("unsealed key should be 32 bytes long, got %d", len(unsealedKey))
	}
	unsealedData, ok := secretbox.Open(nil, data.Data, (*[24]byte)(data.Nonce), (*[32]byte)(unsealedKey))
	if !ok {
		return nil, errors.New("failed to unseal data")
	}

	return &decryptedData{
		Key:  *(*[32]byte)(unsealedKey),
		Data: unsealedData,
	}, nil
}

type tpmSealedData struct {
	Private []byte
	Public  []byte
}

// withSRK runs fn with the loaded Storage Root Key (SRK) handle. The SRK is
// flushed after fn returns.
func withSRK(logf logger.Logf, tpm transport.TPM, fn func(srk tpm2.AuthHandle) error) error {
	srkCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	srkRes, err := srkCmd.Execute(tpm)
	if err != nil {
		return fmt.Errorf("tpm2.CreatePrimary: %w", err)
	}
	defer func() {
		cmd := tpm2.FlushContext{FlushHandle: srkRes.ObjectHandle}
		if _, err := cmd.Execute(tpm); err != nil {
			logf("tpm2.FlushContext: failed to flush SRK handle: %v", err)
		}
	}()

	return fn(tpm2.AuthHandle{
		Handle: srkRes.ObjectHandle,
		Name:   srkRes.Name,
		Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 32),
	})
}

// tpmSeal seals the data using SRK of the local TPM.
func tpmSeal(logf logger.Logf, data []byte) (*tpmSealedData, error) {
	tpm, err := open()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close()

	var res *tpmSealedData
	err = withSRK(logf, tpm, func(srk tpm2.AuthHandle) error {
		sealCmd := tpm2.Create{
			ParentHandle: srk,
			InSensitive: tpm2.TPM2BSensitiveCreate{
				Sensitive: &tpm2.TPMSSensitiveCreate{
					Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
						Buffer: data,
					}),
				},
			},
			InPublic: tpm2.New2B(tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgKeyedHash,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:     true,
					FixedParent:  true,
					UserWithAuth: true,
				},
			}),
		}
		sealRes, err := sealCmd.Execute(tpm)
		if err != nil {
			return fmt.Errorf("tpm2.Create: %w", err)
		}

		res = &tpmSealedData{
			Private: sealRes.OutPrivate.Buffer,
			Public:  sealRes.OutPublic.Bytes(),
		}
		return nil
	})
	return res, err
}

// tpmUnseal unseals the data using SRK of the local TPM.
func tpmUnseal(logf logger.Logf, data *tpmSealedData) ([]byte, error) {
	tpm, err := open()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close()

	var res []byte
	err = withSRK(logf, tpm, func(srk tpm2.AuthHandle) error {
		// Load the sealed object into the TPM first under SRK.
		loadCmd := tpm2.Load{
			ParentHandle: srk,
			InPrivate:    tpm2.TPM2BPrivate{Buffer: data.Private},
			InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](data.Public),
		}
		loadRes, err := loadCmd.Execute(tpm)
		if err != nil {
			return fmt.Errorf("tpm2.Load: %w", err)
		}
		defer func() {
			cmd := tpm2.FlushContext{FlushHandle: loadRes.ObjectHandle}
			if _, err := cmd.Execute(tpm); err != nil {
				log.Printf("tpm2.FlushContext: failed to flush loaded sealed blob handle: %v", err)
			}
		}()

		// Then unseal the object.
		unsealCmd := tpm2.Unseal{
			ItemHandle: tpm2.NamedHandle{
				Handle: loadRes.ObjectHandle,
				Name:   loadRes.Name,
			},
		}
		unsealRes, err := unsealCmd.Execute(tpm)
		if err != nil {
			return fmt.Errorf("tpm2.Unseal: %w", err)
		}
		res = unsealRes.OutData.Buffer

		return nil
	})
	return res, err
}
