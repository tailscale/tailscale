// Copyright (c) 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wf

//go:generate go run generators/gen_guids.go includes/fwpmu.h zguids.go
//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go syscall.go

//go:generate stringer -output=zfieldtype_strings.go -type=fwpmFieldType -trimprefix=fwpmFieldtype
//go:generate stringer -output=zsublayerflags_strings.go -type=fwpmSublayerFlags -trimprefix=fwpmSublayerFlags
//go:generate stringer -output=zfilterenumtype_strings.go -type=filterEnumType -trimprefix=filterEnumType
//go:generate stringer -output=zfilterenumflags_strings.go -type=filterEnumFlags -trimprefix=filterEnumFlags
//go:generate stringer -output=zaction_strings.go -type=Action -trimprefix=Action
//go:generate stringer -output=zfilterflags_strings.go -type=fwpmFilterFlags -trimprefix=fwpmFilterFlags
//go:generate stringer -output=zproviderflags_strings.go -type=fwpmProviderFlags -trimprefix=fwpmProviderFlags
//go:generate stringer -output=zdatatype_strings.go -type=dataType -trimprefix=dataType
//go:generate stringer -output=zconditionflag_strings.go -type=ConditionFlag -trimprefix=ConditionFlag
//go:generate stringer -output=zipproto_strings.go -type=IPProto -trimprefix=IPProto
