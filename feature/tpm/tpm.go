// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tpm implements support for TPM 2.0 devices.
package tpm

import (
	"slices"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"tailscale.com/feature"
	"tailscale.com/hostinfo"
	"tailscale.com/tailcfg"
)

var infoOnce = sync.OnceValue(info)

func init() {
	feature.Register("tpm")
	hostinfo.RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
		hi.TPM = infoOnce()
	})
}

//lint:ignore U1000 used in Linux and Windows builds only
func infoFromCapabilities(tpm transport.TPM) *tailcfg.TPMInfo {
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
