// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package conffile

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	jsonv2 "github.com/go-json-experiment/json"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/opt"
	"tailscale.com/util/mak"
)

// ServicesFile is the [ConfigVersionV1] config file format for Tailscale
// Services. It can describe everything that an [ipn.ServiceConfig] can hold,
// so exporting a Service and applying the file again reproduces the Service.
type ServicesFile struct {
	// Version is the version of the file that was loaded: [ConfigVersionV1],
	// [ConfigVersionV0], or [LegacyVersion]. [LoadServicesFile] converts a
	// [ConfigVersionV0] file to this type and keeps the file's version here.
	// A file that is written out always has [ConfigVersionV1].
	Version string `json:"version"`

	// Services maps a Service name to its configuration.
	Services map[tailcfg.ServiceName]*ServiceFile `json:"services,omitzero"`

	// Legacy holds a raw ipn.ServeConfig parsed from a version-less file (e.g.
	// "tailscale serve status --json" output). It is non-nil only when Version
	// is [LegacyVersion]. It is never serialized.
	Legacy *ipn.ServeConfig `json:"-"`
}

// ServiceFile is the configuration of one Tailscale Service.
type ServiceFile struct {
	// Version is [ConfigVersionV1]. It is set if and only if this ServiceFile
	// is a whole file, not an entry in a [ServicesFile].
	Version string `json:"version,omitzero"`

	// Advertised tells control whether the client thinks it is ready to host
	// the Service. If unset, it is assumed to be true.
	Advertised opt.Bool `json:"advertised,omitzero"`

	// Tun enables TUN (layer 3) mode. Packets for the Service are delivered
	// to the Tailscale network interface and the user handles them. It cannot
	// be combined with Listeners.
	Tun bool `json:"tun,omitzero"`

	// Listeners maps a TCP port of the Service to what tailscaled does with
	// connections to that port.
	Listeners map[uint16]*Listener `json:"listeners,omitzero"`
}

// Listener is what tailscaled does with connections to one port of a Service.
type Listener struct {
	// Protocol is the protocol that tailscaled speaks to the client. It is
	// one of [ProtoHTTP], [ProtoHTTPS], [ProtoTCP], or
	// [ProtoTLSTerminatedTCP]. It says nothing about the back-end.
	Protocol ServiceProtocol `json:"protocol"`

	// Routes maps a mount point ("/", "/api") to the handler for requests
	// under it. It is required for ProtoHTTP and ProtoHTTPS and invalid
	// otherwise.
	Routes map[string]*Route `json:"routes,omitzero"`

	// Forward is where connections are forwarded. It is required for
	// ProtoTCP and ProtoTLSTerminatedTCP and invalid otherwise.
	Forward *Forward `json:"forward,omitzero"`
}

// Route is the handler for one mount point of an HTTP or HTTPS listener.
// Exactly one of Proxy, Path, Text, and Redirect is set.
type Route struct {
	// Proxy is a back-end to reverse proxy to.
	Proxy *ProxyBackend `json:"proxy,omitzero"`

	// Path is the absolute path of a file or directory to serve.
	Path string `json:"path,omitzero"`

	// Text is a plain-text response body.
	Text string `json:"text,omitzero"`

	// Redirect is a URL to redirect to. See [ipn.HTTPHandler.Redirect] for
	// the status code prefix and the expansion variables.
	Redirect string `json:"redirect,omitzero"`

	// AcceptAppCaps lists the peer capabilities that tailscaled forwards to
	// the back-end in a header. It is valid only with Proxy.
	AcceptAppCaps []peercap.Cap `json:"acceptAppCaps,omitzero"`
}

// ProxyBackend is the back-end of a reverse proxy [Route].
type ProxyBackend struct {
	// URL is where the back-end listens. It is an "http://" or "https://"
	// URL, or "unix:<path>" for plain HTTP over a Unix socket.
	URL string `json:"url"`

	// InsecureSkipVerify disables verification of the back-end's TLS
	// certificate. It is valid only with an "https://" URL.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitzero"`

	// HTTP is the HTTP version that tailscaled speaks to the back-end. See
	// [ipn.HTTPHandler.BackendHTTP]. It is empty or [ipn.BackendHTTPH2C].
	// [ipn.BackendHTTPH2C] is invalid with an "https://" URL.
	HTTP string `json:"http,omitzero"`
}

// Forward is the back-end of a TCP or TLS-terminated TCP [Listener].
type Forward struct {
	// Addr is "host:port", or "unix:<path>" for a Unix socket.
	Addr string `json:"addr"`

	// ProxyProtocol is the version of the PROXY protocol header that
	// tailscaled sends before the forwarded bytes: 1, 2, or 0 for none. It
	// is invalid with a Unix socket.
	ProxyProtocol int `json:"proxyProtocol,omitzero"`
}

// LoadServicesFile loads a serve config file of any supported version.
//
// A [ConfigVersionV1] file is returned as written. A [ConfigVersionV0] file is
// converted, and the result keeps the meaning that the file had under that
// version. A version-less file is treated as a legacy raw [ipn.ServeConfig]:
// the result has Version [LegacyVersion], its Legacy field set, and Services
// left nil.
//
// If forService is non-empty, a versioned file is the configuration of that
// one Service ([ServiceFile]) and not a [ServicesFile].
func LoadServicesFile(filename string, forService string) (*ServicesFile, error) {
	json, version, err := readServicesFile(filename)
	if err != nil {
		return nil, err
	}
	switch version {
	case "":
		legacy, err := loadLegacyServeConfig(json)
		if err != nil {
			return nil, err
		}
		return &ServicesFile{Version: LegacyVersion, Legacy: legacy}, nil
	case ConfigVersionV0:
		v0, err := loadConfigV0(json, forService)
		if err != nil {
			return nil, err
		}
		sf := &ServicesFile{Version: ConfigVersionV0}
		for name, details := range v0.Services {
			svc, err := details.toServiceFile()
			if err != nil {
				return nil, fmt.Errorf("service %q: %w", name, err)
			}
			if err := svc.validate(); err != nil {
				return nil, fmt.Errorf("service %q: %w", name, err)
			}
			mak.Set(&sf.Services, name, svc)
		}
		return sf, nil
	case ConfigVersionV1:
		return loadConfigV1(json, forService)
	}
	return nil, fmt.Errorf("unsupported config file version %q", version)
}

func loadConfigV1(json []byte, forService string) (*ServicesFile, error) {
	sf := &ServicesFile{Version: ConfigVersionV1}
	if svcName := tailcfg.AsServiceName(forService); svcName != "" {
		var svc ServiceFile
		if err := jsonv2.Unmarshal(json, &svc, jsonv2.RejectUnknownMembers(true)); err != nil {
			return nil, err
		}
		svc.Version = ""
		mak.Set(&sf.Services, svcName, &svc)
	} else {
		if err := jsonv2.Unmarshal(json, sf, jsonv2.RejectUnknownMembers(true)); err != nil {
			return nil, err
		}
		for svcName, svc := range sf.Services {
			if svc != nil && svc.Version != "" {
				return nil, fmt.Errorf("service %q: services cannot be versioned separately from config file", svcName)
			}
		}
	}
	for svcName, svc := range sf.Services {
		if err := svcName.Validate(); err != nil {
			return nil, err
		}
		if svc == nil {
			return nil, fmt.Errorf("service %q: must not be null", svcName)
		}
		if err := svc.validate(); err != nil {
			return nil, fmt.Errorf("service %q: %w", svcName, err)
		}
	}
	return sf, nil
}

// validate reports whether svc is a configuration that [ServiceFile.ApplyTo]
// can apply.
func (svc *ServiceFile) validate() error {
	if svc.Tun && len(svc.Listeners) > 0 {
		return errors.New("cannot mix TUN mode with listeners")
	}
	for port, lis := range svc.Listeners {
		if err := lis.validate(port); err != nil {
			return fmt.Errorf("listener %d: %w", port, err)
		}
	}
	return nil
}

func (lis *Listener) validate(port uint16) error {
	if lis == nil {
		return errors.New("must not be null")
	}
	if port == 0 {
		return errors.New("port must not be 0")
	}
	switch lis.Protocol {
	case ProtoHTTP, ProtoHTTPS:
		if lis.Forward != nil {
			return fmt.Errorf("protocol %q does not take \"forward\"", lis.Protocol)
		}
		if len(lis.Routes) == 0 {
			return fmt.Errorf("protocol %q requires \"routes\"", lis.Protocol)
		}
		// [ipn.ServeConfig.SetWebHandler] treats "/foo" and "/foo/" as the
		// same mount point, so a file must not name both.
		seen := map[string]string{}
		for mount, r := range lis.Routes {
			if !strings.HasPrefix(mount, "/") {
				return fmt.Errorf("route %q: mount point must start with \"/\"", mount)
			}
			key := strings.TrimSuffix(mount, "/")
			if other, ok := seen[key]; ok {
				return fmt.Errorf("routes %q and %q are the same mount point", min(mount, other), max(mount, other))
			}
			seen[key] = mount
			if err := r.validate(); err != nil {
				return fmt.Errorf("route %q: %w", mount, err)
			}
		}
	case ProtoTCP, ProtoTLSTerminatedTCP:
		if len(lis.Routes) > 0 {
			return fmt.Errorf("protocol %q does not take \"routes\"", lis.Protocol)
		}
		if lis.Forward == nil {
			return fmt.Errorf("protocol %q requires \"forward\"", lis.Protocol)
		}
		if err := lis.Forward.validate(); err != nil {
			return fmt.Errorf("forward: %w", err)
		}
	case "":
		return errors.New("missing \"protocol\"")
	default:
		return fmt.Errorf("unsupported protocol %q", lis.Protocol)
	}
	return nil
}

func (r *Route) validate() error {
	if r == nil {
		return errors.New("must not be null")
	}
	n := 0
	for _, set := range []bool{r.Proxy != nil, r.Path != "", r.Text != "", r.Redirect != ""} {
		if set {
			n++
		}
	}
	if n != 1 {
		return errors.New("must set exactly one of \"proxy\", \"path\", \"text\", \"redirect\"")
	}
	if len(r.AcceptAppCaps) > 0 && r.Proxy == nil {
		return errors.New("\"acceptAppCaps\" requires \"proxy\"")
	}
	if r.Path != "" && !filepath.IsAbs(r.Path) {
		return fmt.Errorf("path %q must be absolute", r.Path)
	}
	if r.Proxy != nil {
		if _, err := r.Proxy.handlerProxy(); err != nil {
			return fmt.Errorf("proxy: %w", err)
		}
	}
	return nil
}

// handlerProxy returns the [ipn.HTTPHandler.Proxy] value for p.
func (p *ProxyBackend) handlerProxy() (string, error) {
	var isHTTPS bool
	switch {
	case strings.HasPrefix(p.URL, "http://"), strings.HasPrefix(p.URL, "unix:"):
	case strings.HasPrefix(p.URL, "https://"):
		isHTTPS = true
	default:
		return "", fmt.Errorf("url %q must start with \"http://\", \"https://\", or \"unix:\"", p.URL)
	}
	if p.InsecureSkipVerify && !isHTTPS {
		return "", errors.New("\"insecureSkipVerify\" requires an \"https://\" url")
	}
	switch p.HTTP {
	case "":
	case ipn.BackendHTTPH2C:
		if isHTTPS {
			return "", errors.New("\"http\": \"h2c\" requires a plaintext url; an \"https://\" back-end negotiates HTTP/2 itself")
		}
	default:
		return "", fmt.Errorf("unsupported \"http\" value %q", p.HTTP)
	}
	target, err := ipn.ExpandProxyTargetValue(p.URL, []string{"http", "https", "unix"}, "http")
	if err != nil {
		return "", fmt.Errorf("url %q: %w", p.URL, err)
	}
	if p.InsecureSkipVerify {
		target = "https+insecure://" + strings.TrimPrefix(target, "https://")
	}
	return target, nil
}

func (f *Forward) validate() error {
	if path, ok := strings.CutPrefix(f.Addr, "unix:"); ok {
		if path == "" {
			return errors.New("unix socket path cannot be empty")
		}
		if f.ProxyProtocol != 0 {
			return errors.New("PROXY protocol is not supported with unix socket targets")
		}
		return nil
	}
	host, portStr, err := net.SplitHostPort(f.Addr)
	if err != nil {
		return fmt.Errorf("addr %q: %w", f.Addr, err)
	}
	if host == "" {
		return fmt.Errorf("addr %q: missing host", f.Addr)
	}
	if port, err := strconv.ParseUint(portStr, 10, 16); err != nil || port == 0 {
		return fmt.Errorf("addr %q: invalid port", f.Addr)
	}
	if f.ProxyProtocol < 0 || f.ProxyProtocol > 2 {
		return fmt.Errorf("unsupported PROXY protocol version %d", f.ProxyProtocol)
	}
	return nil
}

// ApplyTo replaces the configuration of the Service name in sc with svc.
// magicDNSSuffix is the tailnet's MagicDNS suffix, which the Service's
// hostname is built from. ApplyTo does not look at svc.Advertised, which is
// not part of an [ipn.ServeConfig].
//
// If ApplyTo returns an error, sc is unchanged.
func (svc *ServiceFile) ApplyTo(sc *ipn.ServeConfig, name tailcfg.ServiceName, magicDNSSuffix string) error {
	if err := name.Validate(); err != nil {
		return err
	}
	if err := svc.validate(); err != nil {
		return fmt.Errorf("service %q: %w", name, err)
	}
	mak.Set(&sc.Services, name, &ipn.ServiceConfig{Tun: svc.Tun})
	for port, lis := range svc.Listeners {
		switch lis.Protocol {
		case ProtoHTTP, ProtoHTTPS:
			for mount, r := range lis.Routes {
				h := &ipn.HTTPHandler{
					Path:     r.Path,
					Text:     r.Text,
					Redirect: r.Redirect,
				}
				if r.Proxy != nil {
					// validate already checked that this succeeds.
					h.Proxy, _ = r.Proxy.handlerProxy()
					h.BackendHTTP = r.Proxy.HTTP
					h.AcceptAppCaps = r.AcceptAppCaps
				}
				sc.SetWebHandler(h, name.String(), port, mount, lis.Protocol == ProtoHTTPS, magicDNSSuffix)
			}
		case ProtoTCP, ProtoTLSTerminatedTCP:
			sc.SetTCPForwardingForService(port, lis.Forward.Addr, lis.Protocol == ProtoTLSTerminatedTCP, name, lis.Forward.ProxyProtocol, magicDNSSuffix)
		}
	}
	return nil
}

// ServiceFromServeConfig returns the [ServiceFile] that describes cfg, the
// configuration of the Service name. magicDNSSuffix is the tailnet's MagicDNS
// suffix. The result leaves Advertised unset.
//
// It returns an error if cfg holds something that a ServiceFile cannot
// describe. It never drops part of cfg. Applying the result with
// [ServiceFile.ApplyTo] reproduces cfg, except that a proxy target written
// as a bare port or host:port comes back as the "http://" URL it stands for.
func ServiceFromServeConfig(name tailcfg.ServiceName, cfg *ipn.ServiceConfig, magicDNSSuffix string) (*ServiceFile, error) {
	if cfg == nil {
		return nil, fmt.Errorf("service %q: has no configuration", name)
	}
	svc := &ServiceFile{Tun: cfg.Tun}
	if cfg.Tun && (len(cfg.TCP) > 0 || len(cfg.Web) > 0) {
		return nil, fmt.Errorf("service %q: TUN mode is set along with TCP or web handlers", name)
	}
	sniName := fmt.Sprintf("%s.%s", name.WithoutPrefix(), magicDNSSuffix)
	webUsed := 0
	for port, tcp := range cfg.TCP {
		if tcp == nil {
			return nil, fmt.Errorf("service %q: port %d has no handler", name, port)
		}
		lis := new(Listener)
		switch {
		case tcp.TCPForward != "" && (tcp.HTTP || tcp.HTTPS):
			return nil, fmt.Errorf("service %q: port %d is both a TCP forward and a web server", name, port)
		case tcp.TCPForward != "":
			lis.Protocol = ProtoTCP
			if tcp.TerminateTLS != "" {
				if tcp.TerminateTLS != sniName {
					return nil, fmt.Errorf("service %q: port %d terminates TLS for %q, not for the Service's name %q", name, port, tcp.TerminateTLS, sniName)
				}
				lis.Protocol = ProtoTLSTerminatedTCP
			}
			lis.Forward = &Forward{Addr: tcp.TCPForward, ProxyProtocol: tcp.ProxyProtocol}
		case tcp.HTTP != tcp.HTTPS:
			lis.Protocol = ProtoHTTP
			if tcp.HTTPS {
				lis.Protocol = ProtoHTTPS
			}
			web, ok := cfg.Web[ipn.HostPort(net.JoinHostPort(sniName, strconv.Itoa(int(port))))]
			if !ok || web == nil || len(web.Handlers) == 0 {
				return nil, fmt.Errorf("service %q: port %d is a web server with no handlers for %q", name, port, sniName)
			}
			webUsed++
			for mount, h := range web.Handlers {
				r, err := routeFromHandler(h)
				if err != nil {
					return nil, fmt.Errorf("service %q: port %d: mount point %q: %w", name, port, mount, err)
				}
				mak.Set(&lis.Routes, mount, r)
			}
		default:
			return nil, fmt.Errorf("service %q: port %d is neither a TCP forward nor a web server", name, port)
		}
		mak.Set(&svc.Listeners, port, lis)
	}
	if webUsed != len(cfg.Web) {
		return nil, fmt.Errorf("service %q: has web handlers for a name or port that the Service does not listen on", name)
	}
	if err := svc.validate(); err != nil {
		return nil, fmt.Errorf("service %q: %w", name, err)
	}
	return svc, nil
}

func routeFromHandler(h *ipn.HTTPHandler) (*Route, error) {
	if h == nil {
		return nil, errors.New("no handler")
	}
	r := &Route{
		Path:     h.Path,
		Text:     h.Text,
		Redirect: h.Redirect,
	}
	if h.Proxy == "" {
		if len(h.AcceptAppCaps) > 0 || h.BackendHTTP != "" {
			return nil, errors.New("handler sets proxy options without a proxy target")
		}
		return r, nil
	}
	r.Proxy = &ProxyBackend{URL: h.Proxy, HTTP: h.BackendHTTP}
	if rest, ok := strings.CutPrefix(h.Proxy, "https+insecure://"); ok {
		r.Proxy.URL = "https://" + rest
		r.Proxy.InsecureSkipVerify = true
	} else if !strings.Contains(h.Proxy, "://") && !strings.HasPrefix(h.Proxy, "unix:") {
		// tailscaled also accepts a bare port or host:port and treats it
		// as plain HTTP. Write the URL that it stands for.
		if _, err := strconv.ParseUint(h.Proxy, 10, 16); err == nil {
			r.Proxy.URL = "http://127.0.0.1:" + h.Proxy
		} else {
			r.Proxy.URL = "http://" + h.Proxy
		}
	}
	r.AcceptAppCaps = h.AcceptAppCaps
	return r, nil
}

// toServiceFile converts a [ConfigVersionV0] Service to a [ServiceFile]. The
// result has the meaning that set-config gave the V0 file: the scheme of each
// endpoint's target picks both the listener protocol and the back-end.
func (sdf *ServiceDetailsFile) toServiceFile() (*ServiceFile, error) {
	svc := &ServiceFile{Advertised: sdf.Advertised}
	for ppr, ep := range sdf.Endpoints {
		if ep.Protocol == ProtoTUN {
			svc.Tun = true
			continue
		}
		if ppr.Proto != int(ipproto.TCP) {
			return nil, errors.New("source ports must be TCP")
		}
		for port := ppr.Ports.First; ; port++ {
			lis := new(Listener)
			isUnix := strings.HasPrefix(ep.Destination, "unix:")
			// Map the source port range 1-1 to the destination port range.
			hostPort := net.JoinHostPort(ep.Destination, strconv.Itoa(int(ep.DestinationPorts.First+(port-ppr.Ports.First))))
			switch ep.Protocol {
			case ProtoFile:
				lis.Protocol = ProtoHTTPS
				lis.Routes = map[string]*Route{"/": {Path: ep.Destination}}
			case ProtoHTTP, ProtoHTTPS, ProtoHTTPSInsecure:
				lis.Protocol = ProtoHTTPS
				if ep.Protocol == ProtoHTTP {
					lis.Protocol = ProtoHTTP
				}
				p := new(ProxyBackend)
				switch {
				case isUnix:
					p.URL = ep.Destination
				case ep.Protocol == ProtoHTTP:
					p.URL = "http://" + hostPort
				default:
					p.URL = "https://" + hostPort
					p.InsecureSkipVerify = ep.Protocol == ProtoHTTPSInsecure
				}
				lis.Routes = map[string]*Route{"/": {Proxy: p}}
			case ProtoTCP, ProtoTLSTerminatedTCP:
				lis.Protocol = ep.Protocol
				lis.Forward = &Forward{Addr: hostPort}
				if isUnix {
					lis.Forward.Addr = ep.Destination
				}
			default:
				return nil, fmt.Errorf("unsupported protocol %q", ep.Protocol)
			}
			mak.Set(&svc.Listeners, port, lis)
			// Stop here, not in the loop condition, so that a range ending
			// at 65535 does not wrap around to zero.
			if port == ppr.Ports.Last {
				break
			}
		}
	}
	return svc, nil
}
