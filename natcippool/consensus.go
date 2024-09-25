package ippool

import (
	"net/netip"
	"path/filepath"
	"strconv"

	"github.com/tidwall/uhaha"
	"tailscale.com/tailcfg"
)

var specialPort uint16 = 61820

func makeAddrForConsensus(a netip.Addr) string {
	return netip.AddrPortFrom(a, specialPort).String()
}

func JoinConsensus(nodeID string, addr, joinAddr netip.Addr, varRoot string) {
	StartConsensusMember(nodeID, makeAddrForConsensus(addr), makeAddrForConsensus(joinAddr), varRoot)
}

func LeadConsensus(nodeID string, addr netip.Addr, varRoot string) {
	StartConsensusMember(nodeID, makeAddrForConsensus(addr), "", varRoot)
}

// StartConsensusMember has this node join the consensus protocol for handing out ip addresses
func StartConsensusMember(nodeID, addr, joinAddr, varRoot string) {
	var conf uhaha.Config

	conf.Name = "natc"
	// TODO if we don't have a varRoot? don't start?
	conf.DataDir = filepath.Join(varRoot, "consensusdata")

	conf.InitialData = initData()

	// TODO is JSON on disk what we want?
	conf.UseJSONSnapshots = true

	conf.AddWriteCommand("ipcheckout", cmdCheckOut)
	conf.AddReadCommand("domainlookup", cmdLookupDomain)
	//conf.AddWriteCommand("ipcheckin", cmdCheckIn)

	conf.NodeID = nodeID
	conf.Addr = addr
	if joinAddr != "" {
		conf.JoinAddr = joinAddr
	}
	conf.Flag.Custom = true

	uhaha.Main(conf)
}

func initData() *consensusData {
	return &consensusData{
		// TODO get these from the user somehow
		V4Ranges: []netip.Prefix{netip.MustParsePrefix("100.80.0.0/24")},
	}
}

func cmdCheckOut(m uhaha.Machine, args []string) (interface{}, error) {
	data := m.Data().(*consensusData)
	nid, err := strconv.Atoi(args[1]) // TODO probably not really how you get a NodeID from a string
	if err != nil {
		panic(err)
	}
	domain := args[2]
	return data.checkoutAddrForNode(tailcfg.NodeID(nid), domain)
}

func cmdLookupDomain(m uhaha.Machine, args []string) (interface{}, error) {
	data := m.Data().(*consensusData)
	nid, err := strconv.Atoi(args[1]) // TODO probably not really how you get a NodeID from a string
	if err != nil {
		panic(err)
	}
	addrString := args[2]
	addr, err := netip.ParseAddr(addrString)
	if err != nil {
		panic(err)
	}
	return data.lookupDomain(tailcfg.NodeID(nid), addr), nil
}

//func cmdCheckIn(m uhaha.Machine, args []string) (interface{}, error) {
//return 0, nil
//}
