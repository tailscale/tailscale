# Tailscale CLI and daemon dependencies

The following open source dependencies are used to build the [tailscale][] and
[tailscaled][] commands. These are primarily used on Linux and BSD variants as
well as an [option for macOS][].

[tailscale]: https://pkg.go.dev/tailscale.com/cmd/tailscale
[tailscaled]: https://pkg.go.dev/tailscale.com/cmd/tailscaled
[option for macOS]: https://tailscale.com/kb/1065/macos-variants/

## Go Packages

Some packages may only be included on certain architectures or operating systems.


 - [filippo.io/edwards25519](https://pkg.go.dev/filippo.io/edwards25519) ([BSD-3-Clause](https://github.com/FiloSottile/edwards25519/blob/v1.1.0/LICENSE))
 - [github.com/coreos/go-systemd/v22/dbus](https://pkg.go.dev/github.com/coreos/go-systemd/v22/dbus) ([Apache-2.0](https://github.com/coreos/go-systemd/blob/v22.5.0/LICENSE))
 - [github.com/fxamacker/cbor/v2](https://pkg.go.dev/github.com/fxamacker/cbor/v2) ([MIT](https://github.com/fxamacker/cbor/blob/v2.5.0/LICENSE))
 - [github.com/godbus/dbus/v5](https://pkg.go.dev/github.com/godbus/dbus/v5) ([BSD-2-Clause](https://github.com/godbus/dbus/blob/76236955d466/LICENSE))
 - [github.com/golang/groupcache/lru](https://pkg.go.dev/github.com/golang/groupcache/lru) ([Apache-2.0](https://github.com/golang/groupcache/blob/41bb18bfe9da/LICENSE))
 - [github.com/google/uuid](https://pkg.go.dev/github.com/google/uuid) ([BSD-3-Clause](https://github.com/google/uuid/blob/v1.5.0/LICENSE))
 - [github.com/gorilla/csrf](https://pkg.go.dev/github.com/gorilla/csrf) ([BSD-3-Clause](https://github.com/gorilla/csrf/blob/v1.7.2/LICENSE))
 - [github.com/gorilla/securecookie](https://pkg.go.dev/github.com/gorilla/securecookie) ([BSD-3-Clause](https://github.com/gorilla/securecookie/blob/v1.1.2/LICENSE))
 - [github.com/hdevalence/ed25519consensus](https://pkg.go.dev/github.com/hdevalence/ed25519consensus) ([BSD-3-Clause](https://github.com/hdevalence/ed25519consensus/blob/v0.2.0/LICENSE))
 - [github.com/josharian/native](https://pkg.go.dev/github.com/josharian/native) ([MIT](https://github.com/josharian/native/blob/5c7d0dd6ab86/license))
 - [github.com/jsimonetti/rtnetlink](https://pkg.go.dev/github.com/jsimonetti/rtnetlink) ([MIT](https://github.com/jsimonetti/rtnetlink/blob/v1.4.0/LICENSE.md))
 - [github.com/kballard/go-shellquote](https://pkg.go.dev/github.com/kballard/go-shellquote) ([MIT](https://github.com/kballard/go-shellquote/blob/95032a82bc51/LICENSE))
 - [github.com/mattn/go-colorable](https://pkg.go.dev/github.com/mattn/go-colorable) ([MIT](https://github.com/mattn/go-colorable/blob/v0.1.13/LICENSE))
 - [github.com/mattn/go-isatty](https://pkg.go.dev/github.com/mattn/go-isatty) ([MIT](https://github.com/mattn/go-isatty/blob/v0.0.20/LICENSE))
 - [github.com/mdlayher/netlink](https://pkg.go.dev/github.com/mdlayher/netlink) ([MIT](https://github.com/mdlayher/netlink/blob/v1.7.2/LICENSE.md))
 - [github.com/mdlayher/socket](https://pkg.go.dev/github.com/mdlayher/socket) ([MIT](https://github.com/mdlayher/socket/blob/v0.5.0/LICENSE.md))
 - [github.com/miekg/dns](https://pkg.go.dev/github.com/miekg/dns) ([BSD-3-Clause](https://github.com/miekg/dns/blob/v1.1.58/LICENSE))
 - [github.com/mitchellh/go-ps](https://pkg.go.dev/github.com/mitchellh/go-ps) ([MIT](https://github.com/mitchellh/go-ps/blob/v1.0.0/LICENSE.md))
 - [github.com/peterbourgon/ff/v3](https://pkg.go.dev/github.com/peterbourgon/ff/v3) ([Apache-2.0](https://github.com/peterbourgon/ff/blob/v3.4.0/LICENSE))
 - [github.com/skip2/go-qrcode](https://pkg.go.dev/github.com/skip2/go-qrcode) ([MIT](https://github.com/skip2/go-qrcode/blob/da1b6568686e/LICENSE))
 - [github.com/tailscale/goupnp](https://pkg.go.dev/github.com/tailscale/goupnp) ([BSD-2-Clause](https://github.com/tailscale/goupnp/blob/c64d0f06ea05/LICENSE))
 - [github.com/tailscale/web-client-prebuilt](https://pkg.go.dev/github.com/tailscale/web-client-prebuilt) ([BSD-3-Clause](https://github.com/tailscale/web-client-prebuilt/blob/5db17b287bf1/LICENSE))
 - [github.com/tcnksm/go-httpstat](https://pkg.go.dev/github.com/tcnksm/go-httpstat) ([MIT](https://github.com/tcnksm/go-httpstat/blob/v0.2.0/LICENSE))
 - [github.com/toqueteos/webbrowser](https://pkg.go.dev/github.com/toqueteos/webbrowser) ([MIT](https://github.com/toqueteos/webbrowser/blob/v1.2.0/LICENSE.md))
 - [github.com/x448/float16](https://pkg.go.dev/github.com/x448/float16) ([MIT](https://github.com/x448/float16/blob/v0.8.4/LICENSE))
 - [go4.org/mem](https://pkg.go.dev/go4.org/mem) ([Apache-2.0](https://github.com/go4org/mem/blob/4f986261bf13/LICENSE))
 - [go4.org/netipx](https://pkg.go.dev/go4.org/netipx) ([BSD-3-Clause](https://github.com/go4org/netipx/blob/fdeea329fbba/LICENSE))
 - [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) ([BSD-3-Clause](https://cs.opensource.google/go/x/crypto/+/v0.18.0:LICENSE))
 - [golang.org/x/exp/maps](https://pkg.go.dev/golang.org/x/exp/maps) ([BSD-3-Clause](https://cs.opensource.google/go/x/exp/+/1b970713:LICENSE))
 - [golang.org/x/net](https://pkg.go.dev/golang.org/x/net) ([BSD-3-Clause](https://cs.opensource.google/go/x/net/+/v0.20.0:LICENSE))
 - [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) ([BSD-3-Clause](https://cs.opensource.google/go/x/oauth2/+/v0.16.0:LICENSE))
 - [golang.org/x/sync/errgroup](https://pkg.go.dev/golang.org/x/sync/errgroup) ([BSD-3-Clause](https://cs.opensource.google/go/x/sync/+/v0.6.0:LICENSE))
 - [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) ([BSD-3-Clause](https://cs.opensource.google/go/x/sys/+/v0.17.0:LICENSE))
 - [golang.org/x/text](https://pkg.go.dev/golang.org/x/text) ([BSD-3-Clause](https://cs.opensource.google/go/x/text/+/v0.14.0:LICENSE))
 - [golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate) ([BSD-3-Clause](https://cs.opensource.google/go/x/time/+/v0.5.0:LICENSE))
 - [k8s.io/client-go/util/homedir](https://pkg.go.dev/k8s.io/client-go/util/homedir) ([Apache-2.0](https://github.com/kubernetes/client-go/blob/v0.29.1/LICENSE))
 - [nhooyr.io/websocket](https://pkg.go.dev/nhooyr.io/websocket) ([ISC](https://github.com/nhooyr/websocket/blob/v1.8.10/LICENSE.txt))
 - [sigs.k8s.io/yaml](https://pkg.go.dev/sigs.k8s.io/yaml) ([Apache-2.0](https://github.com/kubernetes-sigs/yaml/blob/v1.4.0/LICENSE))
 - [sigs.k8s.io/yaml/goyaml.v2](https://pkg.go.dev/sigs.k8s.io/yaml/goyaml.v2) ([Apache-2.0](https://github.com/kubernetes-sigs/yaml/blob/v1.4.0/goyaml.v2/LICENSE))
 - [software.sslmate.com/src/go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12) ([BSD-3-Clause](https://github.com/SSLMate/go-pkcs12/blob/v0.4.0/LICENSE))
