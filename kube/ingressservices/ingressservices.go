package ingressservices

import "net/netip"

const (
	IngressConfigKey = "ingress-config.json"
)

// Configs contains the desired configuration for egress services keyed by
// service name.
type Configs map[string]Config

func (cfgs *Configs) GetConfig(name string) *Config {
	if cfgs == nil {
		return nil
	}
	if cfg, ok := (*cfgs)[name]; ok {
		return &cfg
	}
	return nil
}

type Status struct {
	Configs Configs `json:"configs,omitempty"`
	PodIPv4 string  `json:"podIPv4,omitempty"`
	PodIPv6 string  `json:"podIPv6,omitempty"`
}

type Mapping struct {
	VIPServiceIP netip.Addr `json:"VIPServiceIP"`
	ClusterIP    netip.Addr `json:"ClusterIP"`
}

// Config is an ingress service configuration.
type Config struct {
	IPv4Mapping *Mapping `json:"IPv4Mapping,omitempty"`
	IPv6Mapping *Mapping `json:"IPv6Mapping,omitempty"`
}
