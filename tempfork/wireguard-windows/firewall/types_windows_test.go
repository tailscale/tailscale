//go:build windows
// +build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"testing"
	"unsafe"
)

func TestWtFwpByteBlobSize(t *testing.T) {

	const actualWtFwpByteBlobSize = unsafe.Sizeof(wtFwpByteBlob{})

	if actualWtFwpByteBlobSize != wtFwpByteBlob_Size {
		t.Errorf("Size of FwpByteBlob is %d, although %d is expected.", actualWtFwpByteBlobSize,
			wtFwpByteBlob_Size)
	}
}

func TestWtFwpByteBlobOffsets(t *testing.T) {

	s := wtFwpByteBlob{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.data)) - sp

	if offset != wtFwpByteBlob_data_Offset {
		t.Errorf("FwpByteBlob.data offset is %d although %d is expected", offset, wtFwpByteBlob_data_Offset)
		return
	}
}

func TestWtFwpmAction0Size(t *testing.T) {

	const actualWtFwpmAction0Size = unsafe.Sizeof(wtFwpmAction0{})

	if actualWtFwpmAction0Size != wtFwpmAction0_Size {
		t.Errorf("Size of wtFwpmAction0 is %d, although %d is expected.", actualWtFwpmAction0Size,
			wtFwpmAction0_Size)
	}
}

func TestWtFwpmAction0Offsets(t *testing.T) {

	s := wtFwpmAction0{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.filterType)) - sp

	if offset != wtFwpmAction0_filterType_Offset {
		t.Errorf("wtFwpmAction0.filterType offset is %d although %d is expected", offset,
			wtFwpmAction0_filterType_Offset)
		return
	}
}

func TestWtFwpBitmapArray64Size(t *testing.T) {

	const actualWtFwpBitmapArray64Size = unsafe.Sizeof(wtFwpBitmapArray64{})

	if actualWtFwpBitmapArray64Size != wtFwpBitmapArray64_Size {
		t.Errorf("Size of wtFwpBitmapArray64 is %d, although %d is expected.", actualWtFwpBitmapArray64Size,
			wtFwpBitmapArray64_Size)
	}
}

func TestWtFwpByteArray6Size(t *testing.T) {

	const actualWtFwpByteArray6Size = unsafe.Sizeof(wtFwpByteArray6{})

	if actualWtFwpByteArray6Size != wtFwpByteArray6_Size {
		t.Errorf("Size of wtFwpByteArray6 is %d, although %d is expected.", actualWtFwpByteArray6Size,
			wtFwpByteArray6_Size)
	}
}

func TestWtFwpByteArray16Size(t *testing.T) {

	const actualWtFwpByteArray16Size = unsafe.Sizeof(wtFwpByteArray16{})

	if actualWtFwpByteArray16Size != wtFwpByteArray16_Size {
		t.Errorf("Size of wtFwpByteArray16 is %d, although %d is expected.", actualWtFwpByteArray16Size,
			wtFwpByteArray16_Size)
	}
}

func TestWtFwpConditionValue0Size(t *testing.T) {

	const actualWtFwpConditionValue0Size = unsafe.Sizeof(wtFwpConditionValue0{})

	if actualWtFwpConditionValue0Size != wtFwpConditionValue0_Size {
		t.Errorf("Size of wtFwpConditionValue0 is %d, although %d is expected.", actualWtFwpConditionValue0Size,
			wtFwpConditionValue0_Size)
	}
}

func TestWtFwpConditionValue0Offsets(t *testing.T) {

	s := wtFwpConditionValue0{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.value)) - sp

	if offset != wtFwpConditionValue0_uint8_Offset {
		t.Errorf("wtFwpConditionValue0.value offset is %d although %d is expected", offset, wtFwpConditionValue0_uint8_Offset)
		return
	}
}

func TestWtFwpV4AddrAndMaskSize(t *testing.T) {

	const actualWtFwpV4AddrAndMaskSize = unsafe.Sizeof(wtFwpV4AddrAndMask{})

	if actualWtFwpV4AddrAndMaskSize != wtFwpV4AddrAndMask_Size {
		t.Errorf("Size of wtFwpV4AddrAndMask is %d, although %d is expected.", actualWtFwpV4AddrAndMaskSize,
			wtFwpV4AddrAndMask_Size)
	}
}

func TestWtFwpV4AddrAndMaskOffsets(t *testing.T) {

	s := wtFwpV4AddrAndMask{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.mask)) - sp

	if offset != wtFwpV4AddrAndMask_mask_Offset {
		t.Errorf("wtFwpV4AddrAndMask.mask offset is %d although %d is expected", offset,
			wtFwpV4AddrAndMask_mask_Offset)
		return
	}
}

func TestWtFwpV6AddrAndMaskSize(t *testing.T) {

	const actualWtFwpV6AddrAndMaskSize = unsafe.Sizeof(wtFwpV6AddrAndMask{})

	if actualWtFwpV6AddrAndMaskSize != wtFwpV6AddrAndMask_Size {
		t.Errorf("Size of wtFwpV6AddrAndMask is %d, although %d is expected.", actualWtFwpV6AddrAndMaskSize,
			wtFwpV6AddrAndMask_Size)
	}
}

func TestWtFwpV6AddrAndMaskOffsets(t *testing.T) {

	s := wtFwpV6AddrAndMask{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.prefixLength)) - sp

	if offset != wtFwpV6AddrAndMask_prefixLength_Offset {
		t.Errorf("wtFwpV6AddrAndMask.prefixLength offset is %d although %d is expected", offset,
			wtFwpV6AddrAndMask_prefixLength_Offset)
		return
	}
}

func TestWtFwpValue0Size(t *testing.T) {

	const actualWtFwpValue0Size = unsafe.Sizeof(wtFwpValue0{})

	if actualWtFwpValue0Size != wtFwpValue0_Size {
		t.Errorf("Size of wtFwpValue0 is %d, although %d is expected.", actualWtFwpValue0Size, wtFwpValue0_Size)
	}
}

func TestWtFwpValue0Offsets(t *testing.T) {

	s := wtFwpValue0{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.value)) - sp

	if offset != wtFwpValue0_value_Offset {
		t.Errorf("wtFwpValue0.value offset is %d although %d is expected", offset, wtFwpValue0_value_Offset)
		return
	}
}

func TestWtFwpmDisplayData0Size(t *testing.T) {

	const actualWtFwpmDisplayData0Size = unsafe.Sizeof(wtFwpmDisplayData0{})

	if actualWtFwpmDisplayData0Size != wtFwpmDisplayData0_Size {
		t.Errorf("Size of wtFwpmDisplayData0 is %d, although %d is expected.", actualWtFwpmDisplayData0Size,
			wtFwpmDisplayData0_Size)
	}
}

func TestWtFwpmDisplayData0Offsets(t *testing.T) {

	s := wtFwpmDisplayData0{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.description)) - sp

	if offset != wtFwpmDisplayData0_description_Offset {
		t.Errorf("wtFwpmDisplayData0.description offset is %d although %d is expected", offset,
			wtFwpmDisplayData0_description_Offset)
		return
	}
}

func TestWtFwpmFilterCondition0Size(t *testing.T) {

	const actualWtFwpmFilterCondition0Size = unsafe.Sizeof(wtFwpmFilterCondition0{})

	if actualWtFwpmFilterCondition0Size != wtFwpmFilterCondition0_Size {
		t.Errorf("Size of wtFwpmFilterCondition0 is %d, although %d is expected.",
			actualWtFwpmFilterCondition0Size, wtFwpmFilterCondition0_Size)
	}
}

func TestWtFwpmFilterCondition0Offsets(t *testing.T) {

	s := wtFwpmFilterCondition0{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.matchType)) - sp

	if offset != wtFwpmFilterCondition0_matchType_Offset {
		t.Errorf("wtFwpmFilterCondition0.matchType offset is %d although %d is expected", offset,
			wtFwpmFilterCondition0_matchType_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.conditionValue)) - sp

	if offset != wtFwpmFilterCondition0_conditionValue_Offset {
		t.Errorf("wtFwpmFilterCondition0.conditionValue offset is %d although %d is expected", offset,
			wtFwpmFilterCondition0_conditionValue_Offset)
		return
	}
}

func TestWtFwpmFilter0Size(t *testing.T) {

	const actualWtFwpmFilter0Size = unsafe.Sizeof(wtFwpmFilter0{})

	if actualWtFwpmFilter0Size != wtFwpmFilter0_Size {
		t.Errorf("Size of wtFwpmFilter0 is %d, although %d is expected.", actualWtFwpmFilter0Size,
			wtFwpmFilter0_Size)
	}
}

func TestWtFwpmFilter0Offsets(t *testing.T) {

	s := wtFwpmFilter0{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.displayData)) - sp

	if offset != wtFwpmFilter0_displayData_Offset {
		t.Errorf("wtFwpmFilter0.displayData offset is %d although %d is expected", offset,
			wtFwpmFilter0_displayData_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.flags)) - sp

	if offset != wtFwpmFilter0_flags_Offset {
		t.Errorf("wtFwpmFilter0.flags offset is %d although %d is expected", offset, wtFwpmFilter0_flags_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.providerKey)) - sp

	if offset != wtFwpmFilter0_providerKey_Offset {
		t.Errorf("wtFwpmFilter0.providerKey offset is %d although %d is expected", offset,
			wtFwpmFilter0_providerKey_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.providerData)) - sp

	if offset != wtFwpmFilter0_providerData_Offset {
		t.Errorf("wtFwpmFilter0.providerData offset is %d although %d is expected", offset,
			wtFwpmFilter0_providerData_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.layerKey)) - sp

	if offset != wtFwpmFilter0_layerKey_Offset {
		t.Errorf("wtFwpmFilter0.layerKey offset is %d although %d is expected", offset,
			wtFwpmFilter0_layerKey_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.subLayerKey)) - sp

	if offset != wtFwpmFilter0_subLayerKey_Offset {
		t.Errorf("wtFwpmFilter0.subLayerKey offset is %d although %d is expected", offset,
			wtFwpmFilter0_subLayerKey_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.weight)) - sp

	if offset != wtFwpmFilter0_weight_Offset {
		t.Errorf("wtFwpmFilter0.weight offset is %d although %d is expected", offset,
			wtFwpmFilter0_weight_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.numFilterConditions)) - sp

	if offset != wtFwpmFilter0_numFilterConditions_Offset {
		t.Errorf("wtFwpmFilter0.numFilterConditions offset is %d although %d is expected", offset,
			wtFwpmFilter0_numFilterConditions_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.filterCondition)) - sp

	if offset != wtFwpmFilter0_filterCondition_Offset {
		t.Errorf("wtFwpmFilter0.filterCondition offset is %d although %d is expected", offset,
			wtFwpmFilter0_filterCondition_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.action)) - sp

	if offset != wtFwpmFilter0_action_Offset {
		t.Errorf("wtFwpmFilter0.action offset is %d although %d is expected", offset,
			wtFwpmFilter0_action_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.providerContextKey)) - sp

	if offset != wtFwpmFilter0_providerContextKey_Offset {
		t.Errorf("wtFwpmFilter0.providerContextKey offset is %d although %d is expected", offset,
			wtFwpmFilter0_providerContextKey_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.reserved)) - sp

	if offset != wtFwpmFilter0_reserved_Offset {
		t.Errorf("wtFwpmFilter0.reserved offset is %d although %d is expected", offset,
			wtFwpmFilter0_reserved_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.filterID)) - sp

	if offset != wtFwpmFilter0_filterID_Offset {
		t.Errorf("wtFwpmFilter0.filterID offset is %d although %d is expected", offset,
			wtFwpmFilter0_filterID_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.effectiveWeight)) - sp

	if offset != wtFwpmFilter0_effectiveWeight_Offset {
		t.Errorf("wtFwpmFilter0.effectiveWeight offset is %d although %d is expected", offset,
			wtFwpmFilter0_effectiveWeight_Offset)
		return
	}
}

func TestWtFwpProvider0Size(t *testing.T) {

	const actualWtFwpProvider0Size = unsafe.Sizeof(wtFwpProvider0{})

	if actualWtFwpProvider0Size != wtFwpProvider0_Size {
		t.Errorf("Size of wtFwpProvider0 is %d, although %d is expected.", actualWtFwpProvider0Size,
			wtFwpProvider0_Size)
	}
}

func TestWtFwpProvider0Offsets(t *testing.T) {

	s := wtFwpProvider0{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.displayData)) - sp

	if offset != wtFwpProvider0_displayData_Offset {
		t.Errorf("wtFwpProvider0.displayData offset is %d although %d is expected", offset,
			wtFwpProvider0_displayData_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.flags)) - sp

	if offset != wtFwpProvider0_flags_Offset {
		t.Errorf("wtFwpProvider0.flags offset is %d although %d is expected", offset,
			wtFwpProvider0_flags_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.providerData)) - sp

	if offset != wtFwpProvider0_providerData_Offset {
		t.Errorf("wtFwpProvider0.providerData offset is %d although %d is expected", offset,
			wtFwpProvider0_providerData_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.serviceName)) - sp

	if offset != wtFwpProvider0_serviceName_Offset {
		t.Errorf("wtFwpProvider0.serviceName offset is %d although %d is expected", offset,
			wtFwpProvider0_serviceName_Offset)
		return
	}
}

func TestWtFwpmSession0Size(t *testing.T) {

	const actualWtFwpmSession0Size = unsafe.Sizeof(wtFwpmSession0{})

	if actualWtFwpmSession0Size != wtFwpmSession0_Size {
		t.Errorf("Size of wtFwpmSession0 is %d, although %d is expected.", actualWtFwpmSession0Size,
			wtFwpmSession0_Size)
	}
}

func TestWtFwpmSession0Offsets(t *testing.T) {

	s := wtFwpmSession0{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.displayData)) - sp

	if offset != wtFwpmSession0_displayData_Offset {
		t.Errorf("wtFwpmSession0.displayData offset is %d although %d is expected", offset,
			wtFwpmSession0_displayData_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.flags)) - sp

	if offset != wtFwpmSession0_flags_Offset {
		t.Errorf("wtFwpmSession0.flags offset is %d although %d is expected", offset, wtFwpmSession0_flags_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.txnWaitTimeoutInMSec)) - sp

	if offset != wtFwpmSession0_txnWaitTimeoutInMSec_Offset {
		t.Errorf("wtFwpmSession0.txnWaitTimeoutInMSec offset is %d although %d is expected", offset,
			wtFwpmSession0_txnWaitTimeoutInMSec_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.processId)) - sp

	if offset != wtFwpmSession0_processId_Offset {
		t.Errorf("wtFwpmSession0.processId offset is %d although %d is expected", offset,
			wtFwpmSession0_processId_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.sid)) - sp

	if offset != wtFwpmSession0_sid_Offset {
		t.Errorf("wtFwpmSession0.sid offset is %d although %d is expected", offset, wtFwpmSession0_sid_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.username)) - sp

	if offset != wtFwpmSession0_username_Offset {
		t.Errorf("wtFwpmSession0.username offset is %d although %d is expected", offset,
			wtFwpmSession0_username_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.kernelMode)) - sp

	if offset != wtFwpmSession0_kernelMode_Offset {
		t.Errorf("wtFwpmSession0.kernelMode offset is %d although %d is expected", offset,
			wtFwpmSession0_kernelMode_Offset)
		return
	}
}

func TestWtFwpmSublayer0Size(t *testing.T) {

	const actualWtFwpmSublayer0Size = unsafe.Sizeof(wtFwpmSublayer0{})

	if actualWtFwpmSublayer0Size != wtFwpmSublayer0_Size {
		t.Errorf("Size of wtFwpmSublayer0 is %d, although %d is expected.", actualWtFwpmSublayer0Size,
			wtFwpmSublayer0_Size)
	}
}

func TestWtFwpmSublayer0Offsets(t *testing.T) {

	s := wtFwpmSublayer0{}
	sp := uintptr(unsafe.Pointer(&s))

	offset := uintptr(unsafe.Pointer(&s.displayData)) - sp

	if offset != wtFwpmSublayer0_displayData_Offset {
		t.Errorf("wtFwpmSublayer0.displayData offset is %d although %d is expected", offset,
			wtFwpmSublayer0_displayData_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.flags)) - sp

	if offset != wtFwpmSublayer0_flags_Offset {
		t.Errorf("wtFwpmSublayer0.flags offset is %d although %d is expected", offset,
			wtFwpmSublayer0_flags_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.providerKey)) - sp

	if offset != wtFwpmSublayer0_providerKey_Offset {
		t.Errorf("wtFwpmSublayer0.providerKey offset is %d although %d is expected", offset,
			wtFwpmSublayer0_providerKey_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.providerData)) - sp

	if offset != wtFwpmSublayer0_providerData_Offset {
		t.Errorf("wtFwpmSublayer0.providerData offset is %d although %d is expected", offset,
			wtFwpmSublayer0_providerData_Offset)
		return
	}

	offset = uintptr(unsafe.Pointer(&s.weight)) - sp

	if offset != wtFwpmSublayer0_weight_Offset {
		t.Errorf("wtFwpmSublayer0.weight offset is %d although %d is expected", offset,
			wtFwpmSublayer0_weight_Offset)
		return
	}
}
