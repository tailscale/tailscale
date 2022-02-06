package iana

// EnterpriseID represents the Enterprise IDs as set by IANA
type EnterpriseID int

// See https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers for values
const (
	EnterpriseIDCiscoSystems     EnterpriseID = 9
	EnterpriseIDCienaCorporation EnterpriseID = 1271
)

var enterpriseIDToStringMap = map[EnterpriseID]string{
	EnterpriseIDCiscoSystems:     "Cisco Systems",
	EnterpriseIDCienaCorporation: "Ciena Corporation",
}

// String returns the vendor name for a given Enterprise ID
func (e EnterpriseID) String() string {
	if vendor := enterpriseIDToStringMap[e]; vendor != "" {
		return vendor
	}
	return "Unknown"
}
