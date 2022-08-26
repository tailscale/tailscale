# Tailscale for macOS/iOS dependencies

The following open source dependencies are used to build Tailscale on [macOS][]
and [iOS][].  See also the dependencies in the [Tailscale CLI][].

[macOS]: https://tailscale.com/kb/1016/install-mac/
[iOS]: https://tailscale.com/kb/1020/install-ios/
[Tailscale CLI]: ./tailscale.md

## Go Packages


 - [filippo.io/edwards25519](https://pkg.go.dev/filippo.io/edwards25519) ([BSD-3-Clause](https://github.com/FiloSottile/edwards25519/blob/v1.0.0-rc.1/LICENSE))
 - [github.com/coreos/go-iptables/iptables](https://pkg.go.dev/github.com/coreos/go-iptables/iptables) ([Apache-2.0](https://github.com/coreos/go-iptables/blob/v0.6.0/LICENSE))
 - [github.com/fxamacker/cbor/v2](https://pkg.go.dev/github.com/fxamacker/cbor/v2) ([MIT](https://github.com/fxamacker/cbor/blob/v2.4.0/LICENSE))
 - [github.com/godbus/dbus/v5](https://pkg.go.dev/github.com/godbus/dbus/v5) ([BSD-2-Clause](https://github.com/godbus/dbus/blob/v5.0.6/LICENSE))
 - [github.com/golang/groupcache/lru](https://pkg.go.dev/github.com/golang/groupcache/lru) ([Apache-2.0](https://github.com/golang/groupcache/blob/41bb18bfe9da/LICENSE))
 - [github.com/google/btree](https://pkg.go.dev/github.com/google/btree) ([Apache-2.0](https://github.com/google/btree/blob/v1.0.1/LICENSE))
 - [github.com/hdevalence/ed25519consensus](https://pkg.go.dev/github.com/hdevalence/ed25519consensus) ([BSD-3-Clause](https://github.com/hdevalence/ed25519consensus/blob/c00d1f31bab3/LICENSE))
 - [github.com/insomniacslk/dhcp](https://pkg.go.dev/github.com/insomniacslk/dhcp) ([BSD-3-Clause](https://github.com/insomniacslk/dhcp/blob/7d93572ebe8e/LICENSE))
 - [github.com/josharian/native](https://pkg.go.dev/github.com/josharian/native) ([MIT](https://github.com/josharian/native/blob/v1.0.0/license))
 - [github.com/jsimonetti/rtnetlink](https://pkg.go.dev/github.com/jsimonetti/rtnetlink) ([MIT](https://github.com/jsimonetti/rtnetlink/blob/d380b505068b/LICENSE.md))
 - [github.com/klauspost/compress/flate](https://pkg.go.dev/github.com/klauspost/compress/flate) ([Apache-2.0](https://github.com/klauspost/compress/blob/v1.15.5/LICENSE))
 - [github.com/kortschak/wol](https://pkg.go.dev/github.com/kortschak/wol) ([BSD-3-Clause](https://github.com/kortschak/wol/blob/da482cc4850a/LICENSE))
 - [github.com/mdlayher/genetlink](https://pkg.go.dev/github.com/mdlayher/genetlink) ([MIT](https://github.com/mdlayher/genetlink/blob/v1.2.0/LICENSE.md))
 - [github.com/mdlayher/netlink](https://pkg.go.dev/github.com/mdlayher/netlink) ([MIT](https://github.com/mdlayher/netlink/blob/v1.6.0/LICENSE.md))
 - [github.com/mdlayher/sdnotify](https://pkg.go.dev/github.com/mdlayher/sdnotify) ([MIT](https://github.com/mdlayher/sdnotify/blob/v1.0.0/LICENSE.md))
 - [github.com/mdlayher/socket](https://pkg.go.dev/github.com/mdlayher/socket) ([MIT](https://github.com/mdlayher/socket/blob/v0.2.3/LICENSE.md))
 - [github.com/mitchellh/go-ps](https://pkg.go.dev/github.com/mitchellh/go-ps) ([MIT](https://github.com/mitchellh/go-ps/blob/v1.0.0/LICENSE.md))
 - [github.com/tailscale/golang-x-crypto](https://pkg.go.dev/github.com/tailscale/golang-x-crypto) ([BSD-3-Clause](https://github.com/tailscale/golang-x-crypto/blob/0b941c09a5e1/LICENSE))
 - [github.com/tailscale/goupnp](https://pkg.go.dev/github.com/tailscale/goupnp) ([BSD-2-Clause](https://github.com/tailscale/goupnp/blob/c64d0f06ea05/LICENSE))
 - [github.com/tailscale/netlink](https://pkg.go.dev/github.com/tailscale/netlink) ([Apache-2.0](https://github.com/tailscale/netlink/blob/cabfb018fe85/LICENSE))
 - [github.com/tcnksm/go-httpstat](https://pkg.go.dev/github.com/tcnksm/go-httpstat) ([MIT](https://github.com/tcnksm/go-httpstat/blob/v0.2.0/LICENSE))
 - [github.com/u-root/uio](https://pkg.go.dev/github.com/u-root/uio) ([BSD-3-Clause](https://github.com/u-root/uio/blob/dac05f7d2cb4/LICENSE))
 - [github.com/vishvananda/netlink/nl](https://pkg.go.dev/github.com/vishvananda/netlink/nl) ([Apache-2.0](https://github.com/vishvananda/netlink/blob/650dca95af54/LICENSE))
 - [github.com/vishvananda/netns](https://pkg.go.dev/github.com/vishvananda/netns) ([Apache-2.0](https://github.com/vishvananda/netns/blob/50045581ed74/LICENSE))
 - [github.com/x448/float16](https://pkg.go.dev/github.com/x448/float16) ([MIT](https://github.com/x448/float16/blob/v0.8.4/LICENSE))
 - [go4.org/mem](https://pkg.go.dev/go4.org/mem) ([Apache-2.0](https://github.com/go4org/mem/blob/4f986261bf13/LICENSE))
 - [go4.org/netipx](https://pkg.go.dev/go4.org/netipx) ([BSD-3-Clause](https://github.com/go4org/netipx/blob/7e7bdc8411bf/LICENSE))
 - [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) ([BSD-3-Clause](https://cs.opensource.google/go/x/crypto/+/6f7dac96:LICENSE))
 - [golang.org/x/exp](https://pkg.go.dev/golang.org/x/exp) ([BSD-3-Clause](https://cs.opensource.google/go/x/exp/+/a9213eeb:LICENSE))
 - [golang.org/x/net](https://pkg.go.dev/golang.org/x/net) ([BSD-3-Clause](https://cs.opensource.google/go/x/net/+/c690dde0:LICENSE))
 - [golang.org/x/sync/errgroup](https://pkg.go.dev/golang.org/x/sync/errgroup) ([BSD-3-Clause](https://cs.opensource.google/go/x/sync/+/0de741cf:LICENSE))
 - [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) ([BSD-3-Clause](https://cs.opensource.google/go/x/sys/+/c0bba94a:LICENSE))
 - [golang.org/x/text](https://pkg.go.dev/golang.org/x/text) ([BSD-3-Clause](https://cs.opensource.google/go/x/text/+/v0.3.7:LICENSE))
 - [golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate) ([BSD-3-Clause](https://cs.opensource.google/go/x/time/+/f0f3c7e8:LICENSE))
 - [golang.zx2c4.com/wireguard](https://pkg.go.dev/golang.zx2c4.com/wireguard) ([MIT](https://git.zx2c4.com/wireguard-go/tree/LICENSE?id=c31a7b1ab478))
 - [gvisor.dev/gvisor/pkg](https://pkg.go.dev/gvisor.dev/gvisor/pkg) ([Apache-2.0](https://github.com/google/gvisor/blob/850e42eb4444/LICENSE))
 - [nhooyr.io/websocket](https://pkg.go.dev/nhooyr.io/websocket) ([MIT](https://github.com/nhooyr/websocket/blob/v1.8.7/LICENSE.txt))
 - [tailscale.com](https://pkg.go.dev/tailscale.com) ([BSD-3-Clause](https://github.com/tailscale/tailscale/blob/HEAD/LICENSE))

## Additional Dependencies

 - [Inter Typeface](https://rsms.me/inter/) ([OFL-1.1](https://github.com/rsms/inter/blob/v3.19/LICENSE.txt))
 - [Sparkle](https://sparkle-project.org/) ([MIT](https://github.com/sparkle-project/Sparkle/blob/2.x/LICENSE))
 - [wireguard-apple](https://git.zx2c4.com/wireguard-apple) ([MIT](https://git.zx2c4.com/wireguard-apple/tree/COPYING))
