// Copyright (c) Tailscale Inc & contributors
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
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/util/mak"
)

// LegacyVersion is the sentinel [ServicesConfigFile.Version] used to mark a
// config that was loaded from the legacy raw [ipn.ServeConfig] format (a
// version-less file, such as "tailscale serve status --json" output). When
// Version is LegacyVersion, [ServicesConfigFile.Legacy] is set and Services is
// nil. It is never written to disk; the on-disk format always uses "0.0.1".
const LegacyVersion = "0.0.0"

// ServicesConfigFile is the config file format for services configuration.
type ServicesConfigFile struct {
	// Version is "0.0.1" for the declarative services configuration file
	// format, or [LegacyVersion] ("0.0.0") when this value was produced by
	// [LoadServicesConfig] from a legacy raw ipn.ServeConfig file (in which
	// case Legacy is set instead of Services).
	Version string `json:"version"`

	Services map[tailcfg.ServiceName]*ServiceDetailsFile `json:"services,omitzero"`

	// Legacy holds a raw ipn.ServeConfig parsed from a version-less file (e.g.
	// "tailscale serve status --json" output). It is non-nil only when Version
	// is [LegacyVersion]. It is an in-memory loading artifact and is never
	// serialized.
	Legacy *ipn.ServeConfig `json:"-"`
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

// LoadServicesConfig loads a serve config file as a [ServicesConfigFile].
//
// If the file has a top-level "version" field it is parsed as that versioned
// declarative format. Otherwise it is treated as a legacy raw [ipn.ServeConfig]
// (such as "tailscale serve status --json" emits): the returned
// ServicesConfigFile has Version [LegacyVersion] and its Legacy field set to the
// parsed raw config, with Services left nil.
//
// forService is used only for the versioned Services configuration file format.
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
	if ver.Version == "" {
		// No "version" field. This is either the legacy raw ipn.ServeConfig
		// (e.g. "tailscale serve status --json" output, which set-config still
		// accepts) or a Services configuration file whose required "version"
		// field was omitted. Distinguish them by the Services config format's
		// lowercase "services"/"endpoints" keys, which never appear in a raw
		// ServeConfig: it uses capitalized "Services" and has no "endpoints"
		// key, and jsonv2 matches case-sensitively. Without this check a
		// version-less Services config file would parse as an empty
		// ServeConfig and silently wipe the existing config.
		var probe struct {
			Services  jsontext.Value `json:"services"`
			Endpoints jsontext.Value `json:"endpoints"`
		}
		if err := jsonv2.Unmarshal(json, &probe); err == nil &&
			(len(probe.Services) > 0 || len(probe.Endpoints) > 0) {
			return nil, errors.New(`config file looks like a Services configuration file but is missing the required "version" field`)
		}
		// Legacy raw ipn.ServeConfig: parse leniently (like set-raw and
		// TS_SERVE_CONFIG) so "serve status --json" round-trips keep working.
		// It is returned wrapped in a ServicesConfigFile with the LegacyVersion
		// sentinel so the public function signature stays stable.
		legacy := new(ipn.ServeConfig)
		if err := jsonv2.Unmarshal(json, legacy); err != nil {
			return nil, fmt.Errorf("could not parse serve config: %w", err)
		}
		return &ServicesConfigFile{Version: LegacyVersion, Legacy: legacy}, nil
	}
	if ver.Version != "0.0.1" {
		return nil, fmt.Errorf("unsupported config file version %q", ver.Version)
	}
	return loadConfigV0(json, forService)
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
