package iana

// StatusCode represents a IANA status code for DHCPv6
//
// IANA Status Codes for DHCPv6
// https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#dhcpv6-parameters-5
type StatusCode uint16

// IANA status codes
const (
	// RFC 3315 par. 24..4
	StatusSuccess       StatusCode = 0
	StatusUnspecFail    StatusCode = 1
	StatusNoAddrsAvail  StatusCode = 2
	StatusNoBinding     StatusCode = 3
	StatusNotOnLink     StatusCode = 4
	StatusUseMulticast  StatusCode = 5
	StatusNoPrefixAvail StatusCode = 6
	// RFC 5007
	StatusUnknownQueryType StatusCode = 7
	StatusMalformedQuery   StatusCode = 8
	StatusNotConfigured    StatusCode = 9
	StatusNotAllowed       StatusCode = 10
	// RFC 5460
	StatusQueryTerminated StatusCode = 11
	// RFC 7653
	StatusDataMissing          StatusCode = 12
	StatusCatchUpComplete      StatusCode = 13
	StatusNotSupported         StatusCode = 14
	StatusTLSConnectionRefused StatusCode = 15
	// RFC 8156
	StatusAddressInUse               StatusCode = 16
	StatusConfigurationConflict      StatusCode = 17
	StatusMissingBindingInformation  StatusCode = 18
	StatusOutdatedBindingInformation StatusCode = 19
	StatusServerShuttingDown         StatusCode = 20
	StatusDNSUpdateNotSupported      StatusCode = 21
	StatusExcessiveTimeSkew          StatusCode = 22
)

// String returns a mnemonic name for a given status code
func (s StatusCode) String() string {
	if sc := statusCodeToStringMap[s]; sc != "" {
		return sc
	}
	return "Unknown"
}

var statusCodeToStringMap = map[StatusCode]string{
	StatusSuccess:       "Success",
	StatusUnspecFail:    "UnspecFail",
	StatusNoAddrsAvail:  "NoAddrsAvail",
	StatusNoBinding:     "NoBinding",
	StatusNotOnLink:     "NotOnLink",
	StatusUseMulticast:  "UseMulticast",
	StatusNoPrefixAvail: "NoPrefixAvail",
	// RFC 5007
	StatusUnknownQueryType: "UnknownQueryType",
	StatusMalformedQuery:   "MalformedQuery",
	StatusNotConfigured:    "NotConfigured",
	StatusNotAllowed:       "NotAllowed",
	// RFC 5460
	StatusQueryTerminated: "QueryTerminated",
	// RFC 7653
	StatusDataMissing:          "DataMissing",
	StatusCatchUpComplete:      "CatchUpComplete",
	StatusNotSupported:         "NotSupported",
	StatusTLSConnectionRefused: "TLSConnectionRefused",
	// RFC 8156
	StatusAddressInUse:               "AddressInUse",
	StatusConfigurationConflict:      "ConfigurationConflict",
	StatusMissingBindingInformation:  "MissingBindingInformation",
	StatusOutdatedBindingInformation: "OutdatedBindingInformation",
	StatusServerShuttingDown:         "ServerShuttingDown",
	StatusDNSUpdateNotSupported:      "DNSUpdateNotSupported",
	StatusExcessiveTimeSkew:          "ExcessiveTimeSkew",
}
