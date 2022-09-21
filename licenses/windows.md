# Tailscale for Windows dependencies

The following open source dependencies are used to build [Tailscale on
Windows][].  See also the dependencies in the [Tailscale CLI][].

[Tailscale on Windows]: https://tailscale.com/kb/1022/install-windows/
[Tailscale CLI]: ./tailscale.md

## Go Packages


 - [filippo.io/edwards25519](https://pkg.go.dev/filippo.io/edwards25519) ([BSD-3-Clause](https://github.com/FiloSottile/edwards25519/blob/v1.0.0-rc.1/LICENSE))
 - [github.com/alexbrainman/sspi](https://pkg.go.dev/github.com/alexbrainman/sspi) ([BSD-3-Clause](https://github.com/alexbrainman/sspi/blob/909beea2cc74/LICENSE))
 - [github.com/apenwarr/fixconsole](https://pkg.go.dev/github.com/apenwarr/fixconsole) ([Apache-2.0](https://github.com/apenwarr/fixconsole/blob/5a9f6489cc29/LICENSE))
 - [github.com/apenwarr/w32](https://pkg.go.dev/github.com/apenwarr/w32) ([BSD-3-Clause](https://github.com/apenwarr/w32/blob/aa00fece76ab/LICENSE))
 - [github.com/fxamacker/cbor/v2](https://pkg.go.dev/github.com/fxamacker/cbor/v2) ([MIT](https://github.com/fxamacker/cbor/blob/v2.4.0/LICENSE))
 - [github.com/golang/groupcache/lru](https://pkg.go.dev/github.com/golang/groupcache/lru) ([Apache-2.0](https://github.com/golang/groupcache/blob/41bb18bfe9da/LICENSE))
 - [github.com/hdevalence/ed25519consensus](https://pkg.go.dev/github.com/hdevalence/ed25519consensus) ([BSD-3-Clause](https://github.com/hdevalence/ed25519consensus/blob/c00d1f31bab3/LICENSE))
 - [github.com/josharian/native](https://pkg.go.dev/github.com/josharian/native) ([MIT](https://github.com/josharian/native/blob/v1.0.0/license))
 - [github.com/jsimonetti/rtnetlink](https://pkg.go.dev/github.com/jsimonetti/rtnetlink) ([MIT](https://github.com/jsimonetti/rtnetlink/blob/d380b505068b/LICENSE.md))
 - [github.com/klauspost/compress](https://pkg.go.dev/github.com/klauspost/compress) ([Apache-2.0](https://github.com/klauspost/compress/blob/v1.15.5/LICENSE))
 - [github.com/klauspost/compress/internal/snapref](https://pkg.go.dev/github.com/klauspost/compress/internal/snapref) ([BSD-3-Clause](https://github.com/klauspost/compress/blob/v1.15.5/internal/snapref/LICENSE))
 - [github.com/klauspost/compress/zstd/internal/xxhash](https://pkg.go.dev/github.com/klauspost/compress/zstd/internal/xxhash) ([MIT](https://github.com/klauspost/compress/blob/v1.15.5/zstd/internal/xxhash/LICENSE.txt))
 - [github.com/lxn/walk](https://pkg.go.dev/github.com/lxn/walk) ([BSD-3-Clause](https://github.com/tailscale/walk/blob/ed127cfb919a/LICENSE))
 - [github.com/lxn/win](https://pkg.go.dev/github.com/lxn/win) ([BSD-3-Clause](https://github.com/tailscale/win/blob/c3f813abca9f/LICENSE))
 - [github.com/mdlayher/netlink](https://pkg.go.dev/github.com/mdlayher/netlink) ([MIT](https://github.com/mdlayher/netlink/blob/v1.6.0/LICENSE.md))
 - [github.com/mdlayher/socket](https://pkg.go.dev/github.com/mdlayher/socket) ([MIT](https://github.com/mdlayher/socket/blob/v0.2.3/LICENSE.md))
 - [github.com/mitchellh/go-ps](https://pkg.go.dev/github.com/mitchellh/go-ps) ([MIT](https://github.com/mitchellh/go-ps/blob/v1.0.0/LICENSE.md))
 - [github.com/skip2/go-qrcode](https://pkg.go.dev/github.com/skip2/go-qrcode) ([MIT](https://github.com/skip2/go-qrcode/blob/da1b6568686e/LICENSE))
 - [github.com/x448/float16](https://pkg.go.dev/github.com/x448/float16) ([MIT](https://github.com/x448/float16/blob/v0.8.4/LICENSE))
 - [go4.org/mem](https://pkg.go.dev/go4.org/mem) ([Apache-2.0](https://github.com/go4org/mem/blob/4f986261bf13/LICENSE))
 - [go4.org/netipx](https://pkg.go.dev/go4.org/netipx) ([BSD-3-Clause](https://github.com/go4org/netipx/blob/7e7bdc8411bf/LICENSE))
 - [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) ([BSD-3-Clause](https://cs.opensource.google/go/x/crypto/+/6f7dac96:LICENSE))
 - [golang.org/x/net](https://pkg.go.dev/golang.org/x/net) ([BSD-3-Clause](https://cs.opensource.google/go/x/net/+/c690dde0:LICENSE))
 - [golang.org/x/sync/errgroup](https://pkg.go.dev/golang.org/x/sync/errgroup) ([BSD-3-Clause](https://cs.opensource.google/go/x/sync/+/0de741cf:LICENSE))
 - [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) ([BSD-3-Clause](https://cs.opensource.google/go/x/sys/+/c0bba94a:LICENSE))
 - [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) ([BSD-3-Clause](https://cs.opensource.google/go/x/term/+/03fcf44c:LICENSE))
 - [golang.zx2c4.com/wintun](https://pkg.go.dev/golang.zx2c4.com/wintun) ([MIT](https://git.zx2c4.com/wintun-go/tree/LICENSE?id=415007cec224))
 - [golang.zx2c4.com/wireguard/windows/tunnel/winipcfg](https://pkg.go.dev/golang.zx2c4.com/wireguard/windows/tunnel/winipcfg) ([MIT](https://git.zx2c4.com/wireguard-windows/tree/COPYING?h=v0.5.3))
 - [gopkg.in/Knetic/govaluate.v3](https://pkg.go.dev/gopkg.in/Knetic/govaluate.v3) ([MIT](Unknown))
 - [tailscale.com](https://pkg.go.dev/tailscale.com) ([BSD-3-Clause](https://github.com/tailscale/tailscale/blob/HEAD/LICENSE))

## Additional Dependencies

 - [Nullsoft Scriptable Install System](https://nsis.sourceforge.io/) ([zlib/libpng](https://nsis.sourceforge.io/License))
 - [Wintun](https://www.wintun.net/) ([Prebuilt Binaries License](https://git.zx2c4.com/wintun/tree/prebuilt-binaries-license.txt))
 - [wireguard-windows](https://git.zx2c4.com/wireguard-windows/) ([MIT](https://git.zx2c4.com/wireguard-windows/tree/COPYING))
