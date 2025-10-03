// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package conffile

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strings"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/util/mak"
)

// ServicesConfigFile is the config file format for services configuration.
type ServicesConfigFile struct {
	// Version is always "0.0.1" and always present.
	Version string `json:"version"`

	Services map[tailcfg.ServiceName]*ServiceDetailsFile `json:"services,omitzero"`
}

// ServiceDetailsFile is the config syntax for an individual Tailscale Service.
type ServiceDetailsFile struct {
	// Version is always "0.0.1", set if and only if this is not inside a
	// [ServiceConfigFile].
	Version string `json:"version,omitzero"`

	// Endpoints are sets of reverse proxy mappings from ProtoPortRanges on a
	// Service to Targets (proto+destination+port) on remote destinations (or
	// localhost).
	// For example, "tcp:443" -> "tcp://localhost:8000" is an endpoint definition
	// mapping traffic on the TCP port 443 of the Service to port 8080 on localhost.
	// The Proto in the key must be populated.
	// As a special case, if the only mapping provided is "*" -> "TUN", that
	// enables TUN/L3 mode, where packets are delivered to the Tailscale network
	// interface with the understanding that the user will deal with them manually.
	Endpoints map[*tailcfg.ProtoPortRange]*Target `json:"endpoints"`

	// Advertised is a flag that tells control whether or not the client thinks
	// it is ready to host a particular Tailscale Service. If unset, it is
	// assumed to be true.
	Advertised opt.Bool `json:"advertised,omitzero"`
}

// ServiceProtocol is the protocol of a Target.
type ServiceProtocol string

const (
	ProtoHTTP             ServiceProtocol = "http"
	ProtoHTTPS            ServiceProtocol = "https"
	ProtoHTTPSInsecure    ServiceProtocol = "https+insecure"
	ProtoTCP              ServiceProtocol = "tcp"
	ProtoTLSTerminatedTCP ServiceProtocol = "tls-terminated-tcp"
	ProtoFile             ServiceProtocol = "file"
	ProtoTUN              ServiceProtocol = "TUN"
)

// Target is a destination for traffic to go to when it arrives at a Tailscale
// Service host.
type Target struct {
	// The protocol over which to communicate with the Destination.
	// Protocol == ProtoTUN is a special case, activating "TUN mode" where
	// packets are delivered to the Tailscale TUN interface and then manually
	// handled by the user.
	Protocol ServiceProtocol

	// If Protocol is ProtoFile, then Destination is a file path.
	// If Protocol is ProtoTUN, then Destination is empty.
	// Otherwise, it is a host.
	Destination string

	// If Protocol is not ProtoFile or ProtoTUN, then DestinationPorts is the
	// set of ports on which to connect to the host referred to by Destination.
	DestinationPorts tailcfg.PortRange
}

// UnmarshalJSON implements [jsonv1.Unmarshaler].
func (t *Target) UnmarshalJSON(buf []byte) error {
	return jsonv2.Unmarshal(buf, t)
}

// UnmarshalJSONFrom implements [jsonv2.UnmarshalerFrom].
func (t *Target) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var str string
	if err := jsonv2.UnmarshalDecode(dec, &str); err != nil {
		return err
	}

	// The TUN case does not look like a standard <url>://<proto> arrangement,
	// so handled separately.
	if str == "TUN" {
		t.Protocol = ProtoTUN
		t.Destination = ""
		t.DestinationPorts = tailcfg.PortRangeAny
		return nil
	}

	proto, rest, found := strings.Cut(str, "://")
	if !found {
		return errors.New("handler not of form <proto>://<destination>")
	}

	switch ServiceProtocol(proto) {
	case ProtoFile:
		target := path.Clean(rest)
		t.Protocol = ProtoFile
		t.Destination = target
		t.DestinationPorts = tailcfg.PortRange{}
	case ProtoHTTP, ProtoHTTPS, ProtoHTTPSInsecure, ProtoTCP, ProtoTLSTerminatedTCP:
		host, portRange, err := tailcfg.ParseHostPortRange(rest)
		if err != nil {
			return err
		}
		t.Protocol = ServiceProtocol(proto)
		t.Destination = host
		t.DestinationPorts = portRange
	default:
		return errors.New("unsupported protocol")
	}

	return nil
}

func (t *Target) MarshalText() ([]byte, error) {
	var out string
	switch t.Protocol {
	case ProtoFile:
		out = fmt.Sprintf("%s://%s", t.Protocol, t.Destination)
	case ProtoTUN:
		out = "TUN"
	case ProtoHTTP, ProtoHTTPS, ProtoHTTPSInsecure, ProtoTCP, ProtoTLSTerminatedTCP:
		out = fmt.Sprintf("%s://%s", t.Protocol, net.JoinHostPort(t.Destination, t.DestinationPorts.String()))
	default:
		return nil, errors.New("unsupported protocol")
	}
	return []byte(out), nil
}

func LoadServicesConfig(filename string, forService string) (*ServicesConfigFile, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var json []byte
	if hujsonStandardize != nil {
		json, err = hujsonStandardize(data)
		if err != nil {
			return nil, err
		}
	} else {
		json = data
	}
	var ver struct {
		Version string `json:"version"`
	}
	if err = jsonv2.Unmarshal(json, &ver); err != nil {
		return nil, fmt.Errorf("could not parse config file version: %w", err)
	}
	switch ver.Version {
	case "":
		return nil, errors.New("config file must have \"version\" field")
	case "0.0.1":
		return loadConfigV0(json, forService)
	}
	return nil, fmt.Errorf("unsupported config file version %q", ver.Version)
}

func loadConfigV0(json []byte, forService string) (*ServicesConfigFile, error) {
	var scf ServicesConfigFile
	if svcName := tailcfg.AsServiceName(forService); svcName != "" {
		var sdf ServiceDetailsFile
		err := jsonv2.Unmarshal(json, &sdf, jsonv2.RejectUnknownMembers(true))
		if err != nil {
			return nil, err
		}
		mak.Set(&scf.Services, svcName, &sdf)

	} else {
		err := jsonv2.Unmarshal(json, &scf, jsonv2.RejectUnknownMembers(true))
		if err != nil {
			return nil, err
		}
	}
	for svcName, svc := range scf.Services {
		if forService == "" && svc.Version != "" {
			return nil, errors.New("services cannot be versioned separately from config file")
		}
		if err := svcName.Validate(); err != nil {
			return nil, err
		}
		if svc.Endpoints == nil {
			return nil, fmt.Errorf("service %q: missing \"endpoints\" field", svcName)
		}
		var sourcePorts []tailcfg.PortRange
		foundTUN := false
		foundNonTUN := false
		for ppr, target := range svc.Endpoints {
			if target.Protocol == "TUN" {
				if ppr.Proto != 0 || ppr.Ports != tailcfg.PortRangeAny {
					return nil, fmt.Errorf("service %q: destination \"TUN\" can only be used with source \"*\"", svcName)
				}
				foundTUN = true
			} else {
				if ppr.Ports.Last-ppr.Ports.First != target.DestinationPorts.Last-target.DestinationPorts.First {
					return nil, fmt.Errorf("service %q: source and destination port ranges must be of equal size", svcName.String())
				}
				foundNonTUN = true
			}
			if foundTUN && foundNonTUN {
				return nil, fmt.Errorf("service %q: cannot mix TUN mode with non-TUN mode", svcName)
			}
			if pr := findOverlappingRange(sourcePorts, ppr.Ports); pr != nil {
				return nil, fmt.Errorf("service %q: source port ranges %q and %q overlap", svcName, pr.String(), ppr.Ports.String())
			}
			sourcePorts = append(sourcePorts, ppr.Ports)
		}
	}
	return &scf, nil
}

// findOverlappingRange finds and returns a reference to a [tailcfg.PortRange]
// in haystack that overlaps with needle. It returns nil if it doesn't find one.
func findOverlappingRange(haystack []tailcfg.PortRange, needle tailcfg.PortRange) *tailcfg.PortRange {
	for _, pr := range haystack {
		if pr.Contains(needle.First) || pr.Contains(needle.Last) || needle.Contains(pr.First) || needle.Contains(pr.Last) {
			return &pr
		}
	}
	return nil
}
