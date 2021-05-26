module tailscale.com

go 1.16

require (
	github.com/alexbrainman/sspi v0.0.0-20210105120005-909beea2cc74
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/coreos/go-iptables v0.6.0
	github.com/frankban/quicktest v1.13.0
	github.com/github/certstore v0.1.0
	github.com/gliderlabs/ssh v0.3.2
	github.com/go-multierror/multierror v1.0.2
	github.com/go-ole/go-ole v1.2.5
	github.com/godbus/dbus/v5 v5.0.4
	github.com/google/go-cmp v0.5.5
	github.com/goreleaser/nfpm v1.10.3
	github.com/jsimonetti/rtnetlink v0.0.0-20210409061457-9561dc9288a7
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/klauspost/compress v1.12.2
	github.com/kr/pty v1.1.8
	github.com/mdlayher/netlink v1.4.0
	github.com/mdlayher/sdnotify v0.0.0-20210228150836-ea3ec207d697
	github.com/miekg/dns v1.1.42
	github.com/pborman/getopt v1.1.0
	github.com/peterbourgon/ff/v2 v2.0.0
	github.com/tailscale/depaware v0.0.0-20201214215404-77d1e9757027
	github.com/tcnksm/go-httpstat v0.2.0
	github.com/toqueteos/webbrowser v1.2.0
	go4.org/mem v0.0.0-20201119185036-c04c5a6ff174
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210525143221-35b2ab0089ea
	golang.org/x/term v0.0.0-20210503060354-a79de5458b56
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	golang.org/x/tools v0.1.2
	golang.zx2c4.com/wireguard v0.0.0-20210525143454-64cb82f2b3f5
	golang.zx2c4.com/wireguard/windows v0.3.15-0.20210525143335-94c0476d63e3
	honnef.co/go/tools v0.1.4
	inet.af/netaddr v0.0.0-20210523191804-d57edf19c517
	inet.af/netstack v0.0.0-20210317161235-a1bf4e56ef22
	inet.af/peercred v0.0.0-20210318190834-4259e17bb763
	inet.af/wf v0.0.0-20210516214145-a5343001b756
	rsc.io/goversion v1.2.0
)

replace github.com/github/certstore => github.com/cyolosecurity/certstore v0.0.0-20200922073901-ece7f1d353c2
