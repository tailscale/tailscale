package iana

// HWType is a hardware type as per RFC 2132 and defined by the IANA.
type HWType uint16

// See IANA for values.
const (
	_ HWType = iota // skip 0
	HWTypeEthernet
	HWTypeExperimentalEthernet
	HWTypeAmateurRadioAX25
	HWTypeProteonTokenRing
	HWTypeChaos
	HWTypeIEEE802
	HWTypeARCNET
	HWTypeHyperchannel
	HWTypeLanstar
	HWTypeAutonet
	HWTypeLocalTalk
	HWTypeLocalNet
	HWTypeUltraLink
	HWTypeSMDS
	HWTypeFrameRelay
	HWTypeATM
	HWTypeHDLC
	HWTypeFibreChannel
	HWTypeATM2
	HWTypeSerialLine
	HWTypeATM3
	HWTypeMILSTD188220
	HWTypeMetricom
	HWTypeIEEE1394
	HWTypeMAPOS
	HWTypeTwinaxial
	HWTypeEUI64
	HWTypeHIPARP
	HWTypeISO7816
	HWTypeARPSec
	HWTypeIPsec
	HWTypeInfiniband
	HWTypeCAI
	HWTypeWiegandInterface
	HWTypePureIP
)

var hwTypeToString = map[HWType]string{
	HWTypeEthernet:             "Ethernet",
	HWTypeExperimentalEthernet: "Experimental Ethernet",
	HWTypeAmateurRadioAX25:     "Amateur Radio AX.25",
	HWTypeProteonTokenRing:     "Proteon ProNET Token Ring",
	HWTypeChaos:                "Chaos",
	HWTypeIEEE802:              "IEEE 802",
	HWTypeARCNET:               "ARCNET",
	HWTypeHyperchannel:         "Hyperchannel",
	HWTypeLanstar:              "Lanstar",
	HWTypeAutonet:              "Autonet Short Address",
	HWTypeLocalTalk:            "LocalTalk",
	HWTypeLocalNet:             "LocalNet",
	HWTypeUltraLink:            "Ultra link",
	HWTypeSMDS:                 "SMDS",
	HWTypeFrameRelay:           "Frame Relay",
	HWTypeATM:                  "ATM",
	HWTypeHDLC:                 "HDLC",
	HWTypeFibreChannel:         "Fibre Channel",
	HWTypeATM2:                 "ATM 2",
	HWTypeSerialLine:           "Serial Line",
	HWTypeATM3:                 "ATM 3",
	HWTypeMILSTD188220:         "MIL-STD-188-220",
	HWTypeMetricom:             "Metricom",
	HWTypeIEEE1394:             "IEEE 1394.1995",
	HWTypeMAPOS:                "MAPOS",
	HWTypeTwinaxial:            "Twinaxial",
	HWTypeEUI64:                "EUI-64",
	HWTypeHIPARP:               "HIPARP",
	HWTypeISO7816:              "IP and ARP over ISO 7816-3",
	HWTypeARPSec:               "ARPSec",
	HWTypeIPsec:                "IPsec tunnel",
	HWTypeInfiniband:           "Infiniband",
	HWTypeCAI:                  "CAI, TIA-102 Project 125 Common Air Interface",
	HWTypeWiegandInterface:     "Wiegand Interface",
	HWTypePureIP:               "Pure IP",
}

// String implements fmt.Stringer.
func (h HWType) String() string {
	hwtype := hwTypeToString[h]
	if hwtype == "" {
		hwtype = "unknown"
	}
	return hwtype
}
