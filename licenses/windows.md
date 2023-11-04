# Tailscale for Windows dependencies

The following open source dependencies are used to build [Tailscale on
Windows][].  See also the dependencies in the [Tailscale CLI][].

[Tailscale on Windows]: https://tailscale.com/kb/1022/install-windows/
[Tailscale CLI]: ./tailscale.md

## Go Packages


 - [filippo.io/edwards25519](https://pkg.go.dev/filippo.io/edwards25519) ([BSD-3-Clause](https://github.com/FiloSottile/edwards25519/blob/v1.0.0/LICENSE))
 - [github.com/alexbrainman/sspi](https://pkg.go.dev/github.com/alexbrainman/sspi) ([BSD-3-Clause](https://github.com/alexbrainman/sspi/blob/1a75b4708caa/LICENSE))
 - [github.com/apenwarr/fixconsole](https://pkg.go.dev/github.com/apenwarr/fixconsole) ([Apache-2.0](https://github.com/apenwarr/fixconsole/blob/5a9f6489cc29/LICENSE))
 - [github.com/apenwarr/w32](https://pkg.go.dev/github.com/apenwarr/w32) ([BSD-3-Clause](https://github.com/apenwarr/w32/blob/aa00fece76ab/LICENSE))
 - [github.com/coreos/go-iptables/iptables](https://pkg.go.dev/github.com/coreos/go-iptables/iptables) ([Apache-2.0](https://github.com/coreos/go-iptables/blob/v0.7.0/LICENSE))
 - [github.com/dblohm7/wingoes](https://pkg.go.dev/github.com/dblohm7/wingoes) ([BSD-3-Clause](https://github.com/dblohm7/wingoes/blob/e994401fc077/LICENSE))
 - [github.com/fxamacker/cbor/v2](https://pkg.go.dev/github.com/fxamacker/cbor/v2) ([MIT](https://github.com/fxamacker/cbor/blob/v2.5.0/LICENSE))
 - [github.com/golang/groupcache/lru](https://pkg.go.dev/github.com/golang/groupcache/lru) ([Apache-2.0](https://github.com/golang/groupcache/blob/41bb18bfe9da/LICENSE))
 - [github.com/google/btree](https://pkg.go.dev/github.com/google/btree) ([Apache-2.0](https://github.com/google/btree/blob/v1.1.2/LICENSE))
 - [github.com/google/nftables](https://pkg.go.dev/github.com/google/nftables) ([Apache-2.0](https://github.com/google/nftables/blob/9aa6fdf5a28c/LICENSE))
 - [github.com/google/uuid](https://pkg.go.dev/github.com/google/uuid) ([BSD-3-Clause](https://github.com/google/uuid/blob/v1.3.1/LICENSE))
 - [github.com/gregjones/httpcache](https://pkg.go.dev/github.com/gregjones/httpcache) ([MIT](https://github.com/gregjones/httpcache/blob/901d90724c79/LICENSE.txt))
 - [github.com/hdevalence/ed25519consensus](https://pkg.go.dev/github.com/hdevalence/ed25519consensus) ([BSD-3-Clause](https://github.com/hdevalence/ed25519consensus/blob/v0.1.0/LICENSE))
 - [github.com/josharian/native](https://pkg.go.dev/github.com/josharian/native) ([MIT](https://github.com/josharian/native/blob/5c7d0dd6ab86/license))
 - [github.com/jsimonetti/rtnetlink](https://pkg.go.dev/github.com/jsimonetti/rtnetlink) ([MIT](https://github.com/jsimonetti/rtnetlink/blob/v1.3.5/LICENSE.md))
 - [github.com/klauspost/compress](https://pkg.go.dev/github.com/klauspost/compress) ([Apache-2.0](https://github.com/klauspost/compress/blob/v1.17.0/LICENSE))
 - [github.com/klauspost/compress/internal/snapref](https://pkg.go.dev/github.com/klauspost/compress/internal/snapref) ([BSD-3-Clause](https://github.com/klauspost/compress/blob/v1.17.0/internal/snapref/LICENSE))
 - [github.com/klauspost/compress/zstd/internal/xxhash](https://pkg.go.dev/github.com/klauspost/compress/zstd/internal/xxhash) ([MIT](https://github.com/klauspost/compress/blob/v1.17.0/zstd/internal/xxhash/LICENSE.txt))
 - [github.com/mdlayher/netlink](https://pkg.go.dev/github.com/mdlayher/netlink) ([MIT](https://github.com/mdlayher/netlink/blob/v1.7.2/LICENSE.md))
 - [github.com/mdlayher/socket](https://pkg.go.dev/github.com/mdlayher/socket) ([MIT](https://github.com/mdlayher/socket/blob/v0.5.0/LICENSE.md))
 - [github.com/miekg/dns](https://pkg.go.dev/github.com/miekg/dns) ([BSD-3-Clause](https://github.com/miekg/dns/blob/v1.1.56/LICENSE))
 - [github.com/mitchellh/go-ps](https://pkg.go.dev/github.com/mitchellh/go-ps) ([MIT](https://github.com/mitchellh/go-ps/blob/v1.0.0/LICENSE.md))
 - [github.com/nfnt/resize](https://pkg.go.dev/github.com/nfnt/resize) ([ISC](https://github.com/nfnt/resize/blob/83c6a9932646/LICENSE))
 - [github.com/peterbourgon/diskv](https://pkg.go.dev/github.com/peterbourgon/diskv) ([MIT](https://github.com/peterbourgon/diskv/blob/v2.0.1/LICENSE))
 - [github.com/skip2/go-qrcode](https://pkg.go.dev/github.com/skip2/go-qrcode) ([MIT](https://github.com/skip2/go-qrcode/blob/da1b6568686e/LICENSE))
 - [github.com/tailscale/go-winio](https://pkg.go.dev/github.com/tailscale/go-winio) ([MIT](https://github.com/tailscale/go-winio/blob/c4f33415bf55/LICENSE))
 - [github.com/tailscale/netlink](https://pkg.go.dev/github.com/tailscale/netlink) ([Apache-2.0](https://github.com/tailscale/netlink/blob/cabfb018fe85/LICENSE))
 - [github.com/tailscale/walk](https://pkg.go.dev/github.com/tailscale/walk) ([BSD-3-Clause](https://github.com/tailscale/walk/blob/dff4ed649e49/LICENSE))
 - [github.com/tailscale/win](https://pkg.go.dev/github.com/tailscale/win) ([BSD-3-Clause](https://github.com/tailscale/win/blob/84569fd814a9/LICENSE))
 - [github.com/tc-hib/winres](https://pkg.go.dev/github.com/tc-hib/winres) ([0BSD](https://github.com/tc-hib/winres/blob/v0.2.1/LICENSE))
 - [github.com/vishvananda/netlink/nl](https://pkg.go.dev/github.com/vishvananda/netlink/nl) ([Apache-2.0](https://github.com/vishvananda/netlink/blob/v1.2.1-beta.2/LICENSE))
 - [github.com/vishvananda/netns](https://pkg.go.dev/github.com/vishvananda/netns) ([Apache-2.0](https://github.com/vishvananda/netns/blob/v0.0.4/LICENSE))
 - [github.com/x448/float16](https://pkg.go.dev/github.com/x448/float16) ([MIT](https://github.com/x448/float16/blob/v0.8.4/LICENSE))
 - [go4.org/mem](https://pkg.go.dev/go4.org/mem) ([Apache-2.0](https://github.com/go4org/mem/blob/4f986261bf13/LICENSE))
 - [go4.org/netipx](https://pkg.go.dev/go4.org/netipx) ([BSD-3-Clause](https://github.com/go4org/netipx/blob/6213f710f925/LICENSE))
 - [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) ([BSD-3-Clause](https://cs.opensource.google/go/x/crypto/+/v0.14.0:LICENSE))
 - [golang.org/x/exp/constraints](https://pkg.go.dev/golang.org/x/exp/constraints) ([BSD-3-Clause](https://cs.opensource.google/go/x/exp/+/92128663:LICENSE))
 - [golang.org/x/image/bmp](https://pkg.go.dev/golang.org/x/image/bmp) ([BSD-3-Clause](https://cs.opensource.google/go/x/image/+/v0.12.0:LICENSE))
 - [golang.org/x/mod](https://pkg.go.dev/golang.org/x/mod) ([BSD-3-Clause](https://cs.opensource.google/go/x/mod/+/v0.12.0:LICENSE))
 - [golang.org/x/net](https://pkg.go.dev/golang.org/x/net) ([BSD-3-Clause](https://cs.opensource.google/go/x/net/+/v0.17.0:LICENSE))
 - [golang.org/x/sync/errgroup](https://pkg.go.dev/golang.org/x/sync/errgroup) ([BSD-3-Clause](https://cs.opensource.google/go/x/sync/+/v0.3.0:LICENSE))
 - [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) ([BSD-3-Clause](https://cs.opensource.google/go/x/sys/+/v0.13.0:LICENSE))
 - [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) ([BSD-3-Clause](https://cs.opensource.google/go/x/term/+/v0.13.0:LICENSE))
 - [golang.org/x/text](https://pkg.go.dev/golang.org/x/text) ([BSD-3-Clause](https://cs.opensource.google/go/x/text/+/v0.13.0:LICENSE))
 - [golang.zx2c4.com/wintun](https://pkg.go.dev/golang.zx2c4.com/wintun) ([MIT](https://git.zx2c4.com/wintun-go/tree/LICENSE?id=0fa3db229ce2))
 - [golang.zx2c4.com/wireguard/windows/tunnel/winipcfg](https://pkg.go.dev/golang.zx2c4.com/wireguard/windows/tunnel/winipcfg) ([MIT](https://git.zx2c4.com/wireguard-windows/tree/COPYING?h=v0.5.3))
 - [gopkg.in/Knetic/govaluate.v3](https://pkg.go.dev/gopkg.in/Knetic/govaluate.v3) ([MIT](https://github.com/Knetic/govaluate/blob/v3.0.0/LICENSE))
 - [tailscale.com](https://pkg.go.dev/tailscale.com) ([BSD-3-Clause](https://github.com/tailscale/tailscale/blob/HEAD/LICENSE))

## Additional Dependencies

 - [Nullsoft Scriptable Install System](https://nsis.sourceforge.io/) ([zlib/libpng](https://nsis.sourceforge.io/License))
 - [Wintun](https://www.wintun.net/) ([Prebuilt Binaries License](https://git.zx2c4.com/wintun/tree/prebuilt-binaries-license.txt))
 - [wireguard-windows](https://git.zx2c4.com/wireguard-windows/) ([MIT](https://git.zx2c4.com/wireguard-windows/tree/COPYING))
