// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package conffile

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
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
	// "tcp:443" -> {"front": "https", "backend": "http://localhost:8000"}
	// instead terminates HTTPS on port 443 in front of it; see [Target].
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
//
// In a file it is a string, "<proto>://<destination>", whose scheme names
// both the listener and how to reach the destination. Where the listener is
// not the one the string implies, such as HTTPS in front of a plain-HTTP
// back-end, it is an object, {"front": "<listener>", "backend": "<string>"}.
type Target struct {
	// Front is the listener's protocol, set only by the object form:
	// ProtoHTTP, ProtoHTTPS, ProtoTCP or ProtoTLSTerminatedTCP. If empty, the
	// listener is the one Protocol implies; see [Target.Listener].
	Front ServiceProtocol

	// The protocol over which to communicate with the Destination.
	// Protocol == ProtoTUN is a special case, activating "TUN mode" where
	// packets are delivered to the Tailscale TUN interface and then manually
	// handled by the user.
	Protocol ServiceProtocol

	// If Protocol is ProtoFile, then Destination is a file path.
	// If Protocol is ProtoTUN, then Destination is empty.
	// If Protocol is ProtoHTTP, ProtoHTTPS, ProtoHTTPSInsecure, ProtoTCP, or
	// ProtoTLSTerminatedTCP and Destination starts with "unix:", it is a Unix
	// socket path (e.g. "unix:/var/run/app.sock" or "unix:relative.sock").
	// Otherwise, it is a host.
	Destination string

	// If Protocol is not ProtoFile or ProtoTUN, then DestinationPorts is the
	// set of ports on which to connect to the host referred to by Destination.
	// For unix socket targets (Destination starting with "unix:"),
	// DestinationPorts is unused and left at the zero value.
	DestinationPorts tailcfg.PortRange
}

// targetObject is the object form of a [Target].
type targetObject struct {
	Front   ServiceProtocol `json:"front"`
	Backend string          `json:"backend"`
}

// UnmarshalJSON implements [jsonv1.Unmarshaler].
func (t *Target) UnmarshalJSON(buf []byte) error {
	return jsonv2.Unmarshal(buf, t)
}

// UnmarshalJSONFrom implements [jsonv2.UnmarshalerFrom].
func (t *Target) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if dec.PeekKind() == '{' {
		var o targetObject
		// Fail on members a later format adds rather than drop them.
		if err := jsonv2.UnmarshalDecode(dec, &o, jsonv2.RejectUnknownMembers(true)); err != nil {
			return err
		}
		return t.parseObject(o)
	}
	var str string
	if err := jsonv2.UnmarshalDecode(dec, &str); err != nil {
		return err
	}
	return t.parseString(str)
}

// parseString reads the string form.
func (t *Target) parseString(str string) error {
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
		if unixPath, ok := strings.CutPrefix(rest, "unix:"); ok {
			if unixPath == "" {
				return errors.New("unix socket path cannot be empty")
			}
			t.Protocol = ServiceProtocol(proto)
			t.Destination = rest
			t.DestinationPorts = tailcfg.PortRange{}
		} else {
			_, portRange, err := tailcfg.ParseHostPortRange(rest)
			if err != nil {
				return err
			}
			// ParseHostPortRange lowercases the host and keeps IPv6 brackets.
			// Keep it as written, unbracketed as net.JoinHostPort expects. An
			// unbracketed IPv6 host, which SplitHostPort rejects, splits at
			// the last colon as ParseHostPortRange does.
			host, _, err := net.SplitHostPort(rest)
			if err != nil {
				host = rest[:strings.LastIndexByte(rest, ':')]
			}
			t.Protocol = ServiceProtocol(proto)
			t.Destination = host
			t.DestinationPorts = portRange
		}
	default:
		return errors.New("unsupported protocol")
	}

	return nil
}

// Listener returns the protocol t is served on: Front, or else the one the
// string form implies, where https+insecure and file are served over HTTPS.
func (t *Target) Listener() ServiceProtocol {
	if t.Front == "" && (t.Protocol == ProtoHTTPSInsecure || t.Protocol == ProtoFile) {
		return ProtoHTTPS
	}
	return cmp.Or(t.Front, t.Protocol)
}

// parseObject reads the object form: backend in the string form, served
// behind the listener front names.
func (t *Target) parseObject(o targetObject) error {
	var b Target
	if err := b.parseString(o.Backend); err != nil {
		return err
	}
	switch o.Front {
	case ProtoHTTP, ProtoHTTPS:
		switch b.Protocol {
		case ProtoHTTP, ProtoHTTPS, ProtoHTTPSInsecure, ProtoFile:
		default:
			return fmt.Errorf("front protocol %q cannot proxy to a %q back-end", o.Front, b.Protocol)
		}
		// tailscaled speaks plain HTTP to a Unix socket.
		if strings.HasPrefix(b.Destination, "unix:") && b.Protocol != ProtoHTTP {
			return fmt.Errorf("unix socket %q must use the %q back-end protocol", b.Destination, ProtoHTTP)
		}
		// set-config serves anything else as a proxy or text target.
		if b.Protocol == ProtoFile && !filepath.IsAbs(b.Destination) {
			return fmt.Errorf("file path %q is not absolute", b.Destination)
		}
	case ProtoTCP, ProtoTLSTerminatedTCP:
		if b.Protocol != ProtoTCP {
			return fmt.Errorf("front protocol %q cannot proxy to a %q back-end", o.Front, b.Protocol)
		}
	default:
		return fmt.Errorf("invalid front protocol %q", o.Front)
	}
	*t = b
	t.Front = o.Front
	return nil
}

// MarshalJSON writes t as the string form, or as the object form if Front
// names a listener other than the one the string implies.
func (t *Target) MarshalJSON() ([]byte, error) {
	s, err := t.MarshalText()
	if err != nil {
		return nil, err
	}
	if implied := (Target{Protocol: t.Protocol}); t.Listener() == implied.Listener() {
		return jsonv2.Marshal(string(s))
	}
	o := targetObject{Front: t.Front, Backend: string(s)}
	// Never write an object the loader refuses.
	if err := new(Target).parseObject(o); err != nil {
		return nil, err
	}
	return jsonv2.Marshal(o)
}

// MarshalText writes t's Protocol and destination in the string form, which
// does not say Front; [Target.MarshalJSON] writes the endpoint.
func (t *Target) MarshalText() ([]byte, error) {
	var out string
	switch t.Protocol {
	case ProtoFile:
		out = fmt.Sprintf("%s://%s", t.Protocol, t.Destination)
	case ProtoTUN:
		out = "TUN"
	case ProtoHTTP, ProtoHTTPS, ProtoHTTPSInsecure, ProtoTCP, ProtoTLSTerminatedTCP:
		if strings.HasPrefix(t.Destination, "unix:") {
			// Unix socket: serialize as e.g. "tcp://unix:/path/to/sock"
			out = fmt.Sprintf("%s://%s", t.Protocol, t.Destination)
		} else {
			out = fmt.Sprintf("%s://%s", t.Protocol, net.JoinHostPort(t.Destination, t.DestinationPorts.String()))
		}
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
		if svc == nil {
			return nil, fmt.Errorf("service %q: must not be null", svcName)
		}
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
			if target == nil {
				return nil, fmt.Errorf("service %q: endpoint %q: must not be null", svcName, ppr.String())
			}
			if target.Protocol == "TUN" {
				if ppr.Proto != 0 || ppr.Ports != tailcfg.PortRangeAny {
					return nil, fmt.Errorf("service %q: destination \"TUN\" can only be used with source \"*\"", svcName)
				}
				foundTUN = true
			} else {
				// Unix socket targets (Destination starting with "unix:" on an
				// HTTP/HTTPS/HTTPSInsecure/TCP/TLSTerminatedTCP inbound protocol)
				// don't have a destination port range; skip the equality check.
				isUnixSocket := strings.HasPrefix(target.Destination, "unix:") &&
					(target.Protocol == ProtoHTTP ||
						target.Protocol == ProtoHTTPS ||
						target.Protocol == ProtoHTTPSInsecure ||
						target.Protocol == ProtoTCP ||
						target.Protocol == ProtoTLSTerminatedTCP)
				if !isUnixSocket {
					if ppr.Ports.Last-ppr.Ports.First != target.DestinationPorts.Last-target.DestinationPorts.First {
						return nil, fmt.Errorf("service %q: source and destination port ranges must be of equal size", svcName.String())
					}
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
