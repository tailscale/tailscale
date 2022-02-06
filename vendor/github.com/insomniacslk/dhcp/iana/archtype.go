package iana

import (
	"fmt"
	"strings"

	"github.com/u-root/uio/uio"
)

// Arch encodes an architecture type per RFC 4578, Section 2.1.
type Arch uint16

// See RFC 4578, 5970, and http://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#processor-architecture
const (
	INTEL_X86PC       Arch = 0
	NEC_PC98          Arch = 1
	EFI_ITANIUM       Arch = 2
	DEC_ALPHA         Arch = 3
	ARC_X86           Arch = 4
	INTEL_LEAN_CLIENT Arch = 5
	EFI_IA32          Arch = 6
	EFI_X86_64        Arch = 7
	EFI_XSCALE        Arch = 8
	EFI_BC            Arch = 9
	EFI_ARM32         Arch = 10
	EFI_ARM64         Arch = 11
	PPC_OPEN_FIRMWARE Arch = 12
	PPC_EPAPR         Arch = 13
	PPC_OPAL          Arch = 14
	EFI_X86_HTTP      Arch = 15
	EFI_X86_64_HTTP   Arch = 16
	EFI_BC_HTTP       Arch = 17
	EFI_ARM32_HTTP    Arch = 18
	EFI_ARM64_HTTP    Arch = 19
	INTEL_X86PC_HTTP  Arch = 20
	UBOOT_ARM32       Arch = 21
	UBOOT_ARM64       Arch = 22
	UBOOT_ARM32_HTTP  Arch = 23
	UBOOT_ARM64_HTTP  Arch = 24
	EFI_RISCV32       Arch = 25
	EFI_RISCV32_HTTP  Arch = 26
	EFI_RISCV64       Arch = 27
	EFI_RISCV64_HTTP  Arch = 28
	EFI_RISCV128      Arch = 29
	EFI_RISCV128_HTTP Arch = 30
	S390_BASIC        Arch = 31
	S390_EXTENDED     Arch = 32
	EFI_MIPS32        Arch = 33
	EFI_MIPS64        Arch = 34
	EFI_SUNWAY32      Arch = 35
	EFI_SUNWAY64      Arch = 36
)

// archTypeToStringMap maps an Arch to a mnemonic name
var archTypeToStringMap = map[Arch]string{
	INTEL_X86PC:       "Intel x86PC",
	NEC_PC98:          "NEC/PC98",
	EFI_ITANIUM:       "EFI Itanium",
	DEC_ALPHA:         "DEC Alpha",
	ARC_X86:           "Arc x86",
	INTEL_LEAN_CLIENT: "Intel Lean Client",
	EFI_IA32:          "EFI IA32",
	EFI_XSCALE:        "EFI Xscale",
	EFI_X86_64:        "EFI x86-64",
	EFI_BC:            "EFI BC",
	EFI_ARM32:         "EFI ARM32",
	EFI_ARM64:         "EFI ARM64",
	PPC_OPEN_FIRMWARE: "PowerPC Open Firmware",
	PPC_EPAPR:         "PowerPC ePAPR",
	PPC_OPAL:          "POWER OPAL v3",
	EFI_X86_HTTP:      "EFI x86 boot from HTTP",
	EFI_X86_64_HTTP:   "EFI x86-64 boot from HTTP",
	EFI_BC_HTTP:       "EFI BC boot from HTTP",
	EFI_ARM32_HTTP:    "EFI ARM32 boot from HTTP",
	EFI_ARM64_HTTP:    "EFI ARM64 boot from HTTP",
	INTEL_X86PC_HTTP:  "Intel x86PC boot from HTTP",
	UBOOT_ARM32:       "U-Boot ARM32",
	UBOOT_ARM64:       "U-Boot ARM64",
	UBOOT_ARM32_HTTP:  "U-boot ARM32 boot from HTTP",
	UBOOT_ARM64_HTTP:  "U-Boot ARM64 boot from HTTP",
	EFI_RISCV32:       "EFI RISC-V 32-bit",
	EFI_RISCV32_HTTP:  "EFI RISC-V 32-bit boot from HTTP",
	EFI_RISCV64:       "EFI RISC-V 64-bit",
	EFI_RISCV64_HTTP:  "EFI RISC-V 64-bit boot from HTTP",
	EFI_RISCV128:      "EFI RISC-V 128-bit",
	EFI_RISCV128_HTTP: "EFI RISC-V 128-bit boot from HTTP",
	S390_BASIC:        "s390 Basic",
	S390_EXTENDED:     "s390 Extended",
	EFI_MIPS32:        "EFI MIPS32",
	EFI_MIPS64:        "EFI MIPS64",
	EFI_SUNWAY32:      "EFI Sunway 32-bit",
	EFI_SUNWAY64:      "EFI Sunway 64-bit",
}

// String returns a mnemonic name for a given architecture type.
func (a Arch) String() string {
	if at := archTypeToStringMap[a]; at != "" {
		return at
	}
	return "unknown"
}

// Archs represents multiple Arch values.
type Archs []Arch

// Contains returns whether b is one of the Archs in a.
func (a Archs) Contains(b Arch) bool {
	for _, t := range a {
		if t == b {
			return true
		}
	}
	return false
}

// ToBytes returns the serialized option defined by RFC 4578 (DHCPv4) and RFC
// 5970 (DHCPv6) as the Client System Architecture Option.
func (a Archs) ToBytes() []byte {
	buf := uio.NewBigEndianBuffer(nil)
	for _, at := range a {
		buf.Write16(uint16(at))
	}
	return buf.Data()
}

// String returns the list of archs in a human-readable manner.
func (a Archs) String() string {
	s := make([]string, 0, len(a))
	for _, arch := range a {
		s = append(s, arch.String())
	}
	return strings.Join(s, ", ")
}

// FromBytes parses a DHCP list of architecture types as defined by RFC 4578
// and RFC 5970.
func (a *Archs) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	if buf.Len() == 0 {
		return fmt.Errorf("must have at least one archtype if option is present")
	}

	*a = make([]Arch, 0, buf.Len()/2)
	for buf.Has(2) {
		*a = append(*a, Arch(buf.Read16()))
	}
	return buf.FinError()
}
