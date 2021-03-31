module tailscale.com

go 1.16

require (
	github.com/alexbrainman/sspi v0.0.0-20180613141037-e580b900e9f5
	github.com/anmitsu/go-shlex v0.0.0-20161002113705-648efa622239 // indirect
	github.com/coreos/go-iptables v0.4.5
	github.com/flynn/go-shlex v0.0.0-20150515145356-3f9db97f8568 // indirect
	github.com/github/certstore v0.1.0
	github.com/gliderlabs/ssh v0.2.2
	github.com/go-multierror/multierror v1.0.2
	github.com/go-ole/go-ole v1.2.4
	github.com/godbus/dbus/v5 v5.0.3
	github.com/google/go-cmp v0.5.4
	github.com/goreleaser/nfpm v1.1.10
	github.com/jsimonetti/rtnetlink v0.0.0-20210212075122-66c871082f2b
	github.com/klauspost/compress v1.10.10
	github.com/kr/pty v1.1.8
	github.com/mdlayher/netlink v1.3.2
	github.com/mdlayher/sdnotify v0.0.0-20200625151349-e4a4f32afc4a
	github.com/miekg/dns v1.1.30
	github.com/pborman/getopt v0.0.0-20190409184431-ee0cd42419d3
	github.com/peterbourgon/ff/v2 v2.0.0
	github.com/pkg/errors v0.9.1 // indirect
	github.com/tailscale/depaware v0.0.0-20201214215404-77d1e9757027
	github.com/tailscale/wireguard-go v0.0.0-20210330200845-4914b4a944c4
	github.com/tcnksm/go-httpstat v0.2.0
	github.com/toqueteos/webbrowser v1.2.0
	go4.org/mem v0.0.0-20201119185036-c04c5a6ff174
	golang.org/x/crypto v0.0.0-20210317152858-513c2a44f670
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210317225723-c4fcb01b228e
	golang.org/x/term v0.0.0-20210317153231-de623e64d2a6
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	golang.org/x/tools v0.0.0-20201211185031-d93e913c1a58
	golang.zx2c4.com/wireguard/windows v0.1.2-0.20201113162609-9b85be97fdf8
	gopkg.in/yaml.v2 v2.2.8 // indirect
	honnef.co/go/tools v0.1.0
	inet.af/netaddr v0.0.0-20210222205655-a1ec2b7b8c44
	inet.af/netstack v0.0.0-20210317161235-a1bf4e56ef22
	inet.af/peercred v0.0.0-20210302202138-56e694897155
	rsc.io/goversion v1.2.0
)

replace github.com/github/certstore => github.com/cyolosecurity/certstore v0.0.0-20200922073901-ece7f1d353c2
