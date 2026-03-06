package conn25

import (
	"fmt"
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/wgengine/filter"
)

func TestWoo(t *testing.T) {
	tip := netip.MustParseAddrPort("1.2.3.4:24")
	mip := netip.MustParseAddrPort("1.2.3.5:24")
	dph := datapathHandler{}
	p := &packet.Parsed{
		Dst: mip,
	}
	// p needs a mip that _is_ assoc w a tip
	r := dph.HandlePacketsFromTunDevice(p)
	if r != filter.Accept {
		t.Fatal("shoulda bin accept")
	}
	if p.Dst != tip {
		t.Fatal("didn't get the dst we thought")
	}
	fmt.Println(r)
	fmt.Println(p)
}

//test p.dst is not a mip
//test p.dst is not a mip but it is valid connector return traffic
// test p.dst is a mip but not assoc with a tip
