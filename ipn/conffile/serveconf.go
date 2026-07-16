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

// Config file format versions.
const (
	// LegacyVersion is the sentinel [ServicesConfigFile.Version] used to mark a
	// config that was loaded from the legacy raw [ipn.ServeConfig] format (a
	// version-less file, such as "tailscale serve status --json" output). When
	// Version is LegacyVersion, [ServicesConfigFile.Legacy] is set and Services
	// is nil. It is never written to disk.
	LegacyVersion = "0.0.0"
	// ConfigVersionV1 is the original format: every endpoint Target is a
	// shorthand string.
	ConfigVersionV1 = "0.0.1"
	// ConfigVersionV2 adds the [Target] object form for endpoints whose back-end
	// protocol differs from the front-end's default. It also fixes the meaning of
	// the bare "https://" shorthand: it now names the front-end listener (an HTTPS
	// front with a plain-HTTP back-end), whereas a 0.0.1 file used it for a TLS
	// back-end. Because that meaning changed, get-config stamps every export V2 so
	// an older client rejects it with a version error rather than misreading it.
	ConfigVersionV2 = "0.0.2"
)

// ServicesConfigFile is the config file format for services configuration.
type ServicesConfigFile struct {
	// Version is [ConfigVersionV1] ("0.0.1"), or [ConfigVersionV2] ("0.0.2")
	// when an endpoint uses the object form (see [Target]), or [LegacyVersion]
	// ("0.0.0") when produced by [LoadServicesConfig] from a legacy raw
	// ipn.ServeConfig file (in which case Legacy is set instead of Services).
	// Always present.
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
	// Version is "0.0.1", or "0.0.2" when an endpoint uses the object form (see
	// [Target]); set if and only if this is not inside a [ServicesConfigFile].
	Version string `json:"version,omitzero"`

	// Endpoints are sets of reverse proxy mappings from ProtoPortRanges on a
	// Service to Targets on remote destinations (or localhost). The key's Proto
	// must be TCP; the front-end (listener) and back-end protocols are carried
	// by the [Target] value.
	// For example, "tcp:443" -> "tcp://localhost:8000" maps TCP traffic on port
	// 443 of the Service to port 8000 on localhost, and "tcp:443" ->
	// "https://localhost:8000" terminates HTTPS on port 443 and proxies to a
	// plain-HTTP back-end on localhost:8000. See [Target] for the full syntax,
	// including the object form used when the back-end protocol differs from the
	// front-end's default.
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
// Service host. It records two independent protocols: the front-end protocol
// that tailscaled terminates for the listener ([Target.Front]) and the back-end
// protocol used to reach the destination ([Target.Backend]).
//
// In JSON a Target is written one of two ways:
//
//   - As a shorthand string "<front>://<host>:<ports>" whenever the back-end
//     protocol is the one implied by the front-end (see [defaultBackend]): for
//     example "https://127.0.0.1:8000" is an HTTPS listener proxying to a
//     plain-HTTP back-end, and "tcp://127.0.0.1:22" is a TCP listener. The
//     special strings "TUN" and "file://<path>" are also shorthands.
//
//     Note that the shorthand scheme names the FRONT-end (listener) protocol,
//     not the back-end: "https://127.0.0.1:8000" terminates TLS at the listener
//     and then connects to the back-end over plaintext HTTP. To proxy to a TLS
//     back-end you must use the object form below; there is no shorthand for it.
//
//   - As an object {"front": "<front>", "backend": "<proto>://<host>:<ports>"}
//     when the back-end protocol differs from the implied default, for example
//     an HTTPS listener proxying to a TLS back-end:
//     {"front": "https", "backend": "https+insecure://127.0.0.1:8443"}.
//
// As a special case, Front == ProtoTUN activates "TUN mode" where packets are
// delivered to the Tailscale TUN interface and then manually handled by the
// user; it has no back-end.
type Target struct {
	// Front is the front-end (listener) protocol that tailscaled terminates:
	// one of ProtoHTTP, ProtoHTTPS, ProtoTCP, ProtoTLSTerminatedTCP, or
	// ProtoTUN.
	Front ServiceProtocol

	// Backend is the protocol used to reach Destination: one of ProtoHTTP,
	// ProtoHTTPS, ProtoHTTPSInsecure, ProtoTCP, or ProtoFile. It is empty when
	// Front is ProtoTUN.
	Backend ServiceProtocol

	// If Backend is ProtoFile, then Destination is a file path.
	// If Front is ProtoTUN, then Destination is empty.
	// Otherwise, it is a host.
	Destination string

	// If Backend is neither ProtoFile nor empty, then DestinationPorts is the
	// set of ports on which to connect to the host referred to by Destination.
	DestinationPorts tailcfg.PortRange
}

// targetObject is the object (non-shorthand) JSON representation of a [Target].
type targetObject struct {
	Front   ServiceProtocol `json:"front"`
	Backend string          `json:"backend"`
}

// defaultBackend returns the back-end protocol implied by a front-end protocol
// when a Target is written using the shorthand string form. A Target whose
// Backend equals this value can be written as a shorthand string; otherwise it
// must be written as an object so the back-end protocol is not lost.
func defaultBackend(front ServiceProtocol) ServiceProtocol {
	switch front {
	case ProtoHTTP, ProtoHTTPS:
		return ProtoHTTP
	case ProtoTCP, ProtoTLSTerminatedTCP:
		return ProtoTCP
	}
	return ""
}

// validFront reports whether p is a valid front-end (listener) protocol.
func validFront(p ServiceProtocol) bool {
	switch p {
	case ProtoHTTP, ProtoHTTPS, ProtoTCP, ProtoTLSTerminatedTCP, ProtoTUN:
		return true
	}
	return false
}

// validBackendForFront reports whether backend is a legal back-end protocol for
// the given front-end (listener) protocol. It is the single source of truth for
// front/back-end coherence and tracks the subset of the serve apply path that
// the config file format can represent:
//
//   - Web fronts (HTTP, HTTPS) proxy via applyWebServe. Its
//     ExpandProxyTargetValue allowlist also includes "unix", but unix-socket
//     back-ends have no representation in the config file format, so the
//     representable web back-ends are {http, https, https+insecure} plus a file
//     back-end served as a static root.
//   - TCP fronts (TCP, TLS-terminated TCP) forward via applyTCPServe, whose
//     allowlist is {tcp} only.
//   - TUN has no back-end.
//
// A combination this rejects would otherwise parse cleanly but fail later with
// a confusing low-level error from ExpandProxyTargetValue (see #19724).
func validBackendForFront(front, backend ServiceProtocol) bool {
	switch front {
	case ProtoHTTP, ProtoHTTPS:
		switch backend {
		case ProtoHTTP, ProtoHTTPS, ProtoHTTPSInsecure, ProtoFile:
			return true
		}
	case ProtoTCP, ProtoTLSTerminatedTCP:
		return backend == ProtoTCP
	case ProtoTUN:
		return backend == ""
	}
	return false
}

// parseTarget parses a "<proto>://<destination>" spec (or "file://<path>") into
// its protocol, destination, and ports.
func parseTarget(str string) (proto ServiceProtocol, dest string, ports tailcfg.PortRange, err error) {
	p, rest, found := strings.Cut(str, "://")
	if !found {
		return "", "", tailcfg.PortRange{}, errors.New("handler not of form <proto>://<destination>")
	}
	switch ServiceProtocol(p) {
	case ProtoFile:
		return ProtoFile, path.Clean(rest), tailcfg.PortRange{}, nil
	case ProtoHTTP, ProtoHTTPS, ProtoHTTPSInsecure, ProtoTCP, ProtoTLSTerminatedTCP:
		host, portRange, err := tailcfg.ParseHostPortRange(rest)
		if err != nil {
			return "", "", tailcfg.PortRange{}, err
		}
		return ServiceProtocol(p), host, portRange, nil
	}
	return "", "", tailcfg.PortRange{}, errors.New("unsupported protocol")
}

// UnmarshalJSON implements [jsonv1.Unmarshaler].
func (t *Target) UnmarshalJSON(buf []byte) error {
	return jsonv2.Unmarshal(buf, t)
}

// UnmarshalJSONFrom implements [jsonv2.UnmarshalerFrom]. It accepts either the
// shorthand string form or the {"front","backend"} object form.
func (t *Target) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	switch dec.PeekKind() {
	case '"':
		var str string
		if err := jsonv2.UnmarshalDecode(dec, &str); err != nil {
			return err
		}
		return t.fromShorthand(str)
	case '{':
		var o targetObject
		if err := jsonv2.UnmarshalDecode(dec, &o, jsonv2.RejectUnknownMembers(true)); err != nil {
			return err
		}
		return t.fromObject(o)
	default:
		return errors.New("endpoint target must be a string or an object")
	}
}

// fromShorthand populates t from the shorthand string form. The scheme names
// the front-end listener for real front protocols; for the back-end-only
// schemes (https+insecure, file) the front is HTTPS and the scheme names the
// back-end.
func (t *Target) fromShorthand(str string) error {
	// The TUN case does not look like a standard <proto>://<dest> arrangement,
	// so it is handled separately.
	if str == "TUN" {
		t.Front = ProtoTUN
		t.Backend = ""
		t.Destination = ""
		t.DestinationPorts = tailcfg.PortRangeAny
		return nil
	}

	proto, dest, ports, err := parseTarget(str)
	if err != nil {
		return err
	}
	switch proto {
	case ProtoHTTP, ProtoHTTPS, ProtoTCP, ProtoTLSTerminatedTCP:
		t.Front = proto
		t.Backend = defaultBackend(proto)
	case ProtoHTTPSInsecure:
		t.Front = ProtoHTTPS
		t.Backend = ProtoHTTPSInsecure
	case ProtoFile:
		t.Front = ProtoHTTPS
		t.Backend = ProtoFile
	default:
		return errors.New("unsupported protocol")
	}
	if !validBackendForFront(t.Front, t.Backend) {
		return fmt.Errorf("front protocol %q cannot proxy to a %q back-end", t.Front, t.Backend)
	}
	t.Destination = dest
	t.DestinationPorts = ports
	return nil
}

// fromObject populates t from the object form.
func (t *Target) fromObject(o targetObject) error {
	if !validFront(o.Front) || o.Front == ProtoTUN {
		return fmt.Errorf("invalid front protocol %q", o.Front)
	}
	proto, dest, ports, err := parseTarget(o.Backend)
	if err != nil {
		return err
	}
	if !validBackendForFront(o.Front, proto) {
		return fmt.Errorf("front protocol %q cannot proxy to a %q back-end", o.Front, proto)
	}
	t.Front = o.Front
	t.Backend = proto
	t.Destination = dest
	t.DestinationPorts = ports
	return nil
}

// MarshalJSON implements [jsonv1.Marshaler]. It emits the shorthand string form
// when the back-end protocol is the one implied by the front-end, and the
// object form otherwise so that the back-end protocol is preserved.
func (t *Target) MarshalJSON() ([]byte, error) {
	if s, ok := t.shorthand(); ok {
		return jsonv2.Marshal(s)
	}
	// Never emit an object form we would refuse to read back: the back-end must
	// be coherent with the front (this also rejects an invalid front or a TUN
	// front, neither of which has an object form).
	if !validBackendForFront(t.Front, t.Backend) {
		return nil, fmt.Errorf("front protocol %q cannot proxy to a %q back-end", t.Front, t.Backend)
	}
	return jsonv2.Marshal(targetObject{Front: t.Front, Backend: t.backendSpec()})
}

// backendSpec renders the back-end as a "<proto>://<destination>" spec.
func (t *Target) backendSpec() string {
	if t.Backend == ProtoFile {
		return fmt.Sprintf("%s://%s", ProtoFile, t.Destination)
	}
	return fmt.Sprintf("%s://%s", t.Backend, net.JoinHostPort(t.Destination, t.DestinationPorts.String()))
}

// shorthand returns the shorthand string form of t and whether it is
// representable as a shorthand (i.e. the back-end is the default for the front,
// or one of the back-end-only schemes paired with an HTTPS front).
func (t *Target) shorthand() (string, bool) {
	switch t.Front {
	case ProtoTUN:
		return "TUN", true
	case ProtoHTTP, ProtoHTTPS:
		switch {
		case t.Backend == ProtoFile && t.Front == ProtoHTTPS:
			return fmt.Sprintf("%s://%s", ProtoFile, t.Destination), true
		case t.Backend == ProtoHTTPSInsecure && t.Front == ProtoHTTPS:
			return fmt.Sprintf("%s://%s", ProtoHTTPSInsecure, net.JoinHostPort(t.Destination, t.DestinationPorts.String())), true
		case t.Backend == "" || t.Backend == defaultBackend(t.Front):
			return fmt.Sprintf("%s://%s", t.Front, net.JoinHostPort(t.Destination, t.DestinationPorts.String())), true
		}
		return "", false
	case ProtoTCP, ProtoTLSTerminatedTCP:
		if t.Backend == "" || t.Backend == defaultBackend(t.Front) {
			return fmt.Sprintf("%s://%s", t.Front, net.JoinHostPort(t.Destination, t.DestinationPorts.String())), true
		}
		return "", false
	}
	return "", false
}

// LoadServicesConfig loads a serve config file as a [ServicesConfigFile].
//
// If the file has a top-level "version" field it is parsed as that versioned
// declarative format (ConfigVersionV1 or ConfigVersionV2). Otherwise it is
// treated as a legacy raw [ipn.ServeConfig] (such as "tailscale serve status
// --json" emits): the returned ServicesConfigFile has Version LegacyVersion and
// its Legacy field set to the parsed raw config, with Services left nil.
//
// It also returns any non-fatal migration warnings (e.g. an "https://"
// shorthand read from a ConfigVersionV1 file, whose meaning changed in
// ConfigVersionV2) for the caller to surface to the user.
//
// forService is used only for the versioned Services configuration file format.
func LoadServicesConfig(filename string, forService string) (cfg *ServicesConfigFile, warnings []string, err error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}
	var json []byte
	if hujsonStandardize != nil {
		json, err = hujsonStandardize(data)
		if err != nil {
			return nil, nil, err
		}
	} else {
		json = data
	}
	var ver struct {
		Version string `json:"version"`
	}
	if err = jsonv2.Unmarshal(json, &ver); err != nil {
		return nil, nil, fmt.Errorf("could not parse config file version: %w", err)
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
			return nil, nil, errors.New(`config file looks like a Services configuration file but is missing the required "version" field`)
		}
		// Legacy raw ipn.ServeConfig: parse leniently (like set-raw and
		// TS_SERVE_CONFIG) so "serve status --json" round-trips keep working.
		// It is returned wrapped in a ServicesConfigFile with the LegacyVersion
		// sentinel so the public function signature stays stable.
		legacy := new(ipn.ServeConfig)
		if err := jsonv2.Unmarshal(json, legacy); err != nil {
			return nil, nil, fmt.Errorf("could not parse serve config: %w", err)
		}
		return &ServicesConfigFile{Version: LegacyVersion, Legacy: legacy}, nil, nil
	}
	switch ver.Version {
	case ConfigVersionV1, ConfigVersionV2:
		// Both versions share a parse path; the object form is self-describing,
		// so a file is accepted regardless of which version it declares. The
		// version is passed through so the meaning of an "https://" shorthand
		// can be resolved per-version (see loadConfigV0).
		return loadConfigV0(json, forService, ver.Version)
	}
	return nil, nil, fmt.Errorf("unsupported config file version %q", ver.Version)
}

// loadConfigV0 parses and validates a 0.0.x config. version is the declared
// file version, used to resolve the meaning of an "https://" shorthand: in
// 0.0.1 it named a TLS back-end, whereas in 0.0.2 it names an HTTPS front end
// with a plain-HTTP back-end. For a 0.0.1 file each such endpoint is rewritten
// to its legacy meaning and a migration warning is returned.
func loadConfigV0(json []byte, forService, version string) (cfg *ServicesConfigFile, warnings []string, err error) {
	var scf ServicesConfigFile
	if svcName := tailcfg.AsServiceName(forService); svcName != "" {
		var sdf ServiceDetailsFile
		err := jsonv2.Unmarshal(json, &sdf, jsonv2.RejectUnknownMembers(true))
		if err != nil {
			return nil, nil, err
		}
		mak.Set(&scf.Services, svcName, &sdf)

	} else {
		err := jsonv2.Unmarshal(json, &scf, jsonv2.RejectUnknownMembers(true))
		if err != nil {
			return nil, nil, err
		}
	}
	for svcName, svc := range scf.Services {
		if forService == "" && svc.Version != "" {
			return nil, nil, errors.New("services cannot be versioned separately from config file")
		}
		if err := svcName.Validate(); err != nil {
			return nil, nil, err
		}
		if svc.Endpoints == nil {
			return nil, nil, fmt.Errorf("service %q: missing \"endpoints\" field", svcName)
		}
		var sourcePorts []tailcfg.PortRange
		foundTUN := false
		foundNonTUN := false
		for ppr, target := range svc.Endpoints {
			// The bare "https://" shorthand is read with the fixed meaning (an
			// HTTPS front with a plain-HTTP back-end) regardless of version. In a
			// 0.0.1 file it formerly named a TLS back-end, so warn: this is the one
			// shorthand whose meaning changed, and a 0.0.1 file that intended a TLS
			// back-end will now connect in plaintext until it is re-exported with
			// the back-end recorded explicitly. The object form did not exist in
			// 0.0.1, so a real 0.0.1 file only reaches this state via the shorthand.
			if version == ConfigVersionV1 && target.Front == ProtoHTTPS && target.Backend == ProtoHTTP {
				warnings = append(warnings, fmt.Sprintf(
					"service %q: endpoint %q uses the \"https://\" shorthand from a %s file; its meaning changed in %s and it is now read as an HTTPS front end with a plain-HTTP back-end. If you intended a TLS back-end, set it explicitly and re-export with this client.",
					svcName, ppr.String(), ConfigVersionV1, ConfigVersionV2))
			}
			if target.Front == ProtoTUN {
				if ppr.Proto != 0 || ppr.Ports != tailcfg.PortRangeAny {
					return nil, nil, fmt.Errorf("service %q: destination \"TUN\" can only be used with source \"*\"", svcName)
				}
				foundTUN = true
			} else {
				if ppr.Ports.Last-ppr.Ports.First != target.DestinationPorts.Last-target.DestinationPorts.First {
					return nil, nil, fmt.Errorf("service %q: source and destination port ranges must be of equal size", svcName.String())
				}
				foundNonTUN = true
			}
			if foundTUN && foundNonTUN {
				return nil, nil, fmt.Errorf("service %q: cannot mix TUN mode with non-TUN mode", svcName)
			}
			if pr := findOverlappingRange(sourcePorts, ppr.Ports); pr != nil {
				return nil, nil, fmt.Errorf("service %q: source port ranges %q and %q overlap", svcName, pr.String(), ppr.Ports.String())
			}
			sourcePorts = append(sourcePorts, ppr.Ports)
		}
	}
	return &scf, warnings, nil
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
