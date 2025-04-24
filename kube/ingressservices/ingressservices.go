package ingressservices

import "net/netip"

const (
	IngressConfigKey = "ingress-config.json"
)

// Configs contains the desired configuration for egress services keyed by
// service name.
type Configs map[string]Config

type Mapping map[netip.Addr]netip.Addr

// Config is an ingress service configuration.
type Config struct {
	IPv4Mapping Mapping `json:"IPv4Mapping"`
	IPv6Mapping Mapping `json:"IPv6Mapping"`
}
