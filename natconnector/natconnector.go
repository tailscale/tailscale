package natconnector

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"

	"github.com/inetaf/tcpproxy"
	"golang.org/x/net/dns/dnsmessage"
	ippool "tailscale.com/natcippool"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

type NatConnector struct {
	logf            logger.Logf
	ConsensusClient *ippool.ConsensusClient
	whoIs           func(string, netip.AddrPort) (tailcfg.NodeView, tailcfg.UserProfile, bool)
}

func (n *NatConnector) HandleDNSQuery(ctx context.Context, query []byte, remoteAddr netip.AddrPort) ([]byte, error, bool) {
	// TODO even though because of the way the netmap instructions for dns work we can expect only to
	// get dns requests for domains that are configured in the acls, we should probably check the domain
	// here anyway
	// edit: actually I wonder if there are cases we might end up getting a req through here that isn't for us, just
	// because a node is offering a nat connector does that mean all doh queries are for the nat connector?

	var msg dnsmessage.Message
	err := msg.Unpack(query)
	if err != nil {
		log.Printf("HandleDNSQuery: dnsmessage unpack failed: %v\n ", err)
		return nil, err, true
	}

	// who's asking?
	nodeView, _, ok := n.whoIs("", remoteAddr)
	if !ok {
		log.Printf("HandleDNSQuery: WhoIs invalid for: %v\n", remoteAddr)
		return nil, errors.New("invalid remoteAddr"), true // TODO
	}

	domain := msg.Questions[0].Name.String()

	// get them their address
	s, err := n.ConsensusClient.CheckOut(nodeView.ID(), domain)
	if err != nil {
		log.Printf("HandleDNSQuery: consensus CheckOut error: %v\n", err)
		return nil, err, true
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		log.Printf("HandleDNSQuery: parse addr error: %v\n", err)
		return nil, err, true
	}

	//make the msg to return
	bs, err := dnsResponse(&msg, []netip.Addr{addr})
	if err != nil {
		log.Printf("HandleDNSQuery: generateDNSResponse error: %v\n", err)
		return nil, err, true
	}

	return bs, nil, true
}

var tsMBox = dnsmessage.MustNewName("support.tailscale.com.")

// TODO copied from natc.go - we have no TypeAAAA at the moment, will be broken in that case I guess
// dnsResponse makes a DNS response for the natc. If the dnsmessage is requesting TypeAAAA
// or TypeA the provided addrs of the requested type will be used.
func dnsResponse(req *dnsmessage.Message, addrs []netip.Addr) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil,
		dnsmessage.Header{
			ID:            req.Header.ID,
			Response:      true,
			Authoritative: true,
		})
	b.EnableCompression()

	if len(req.Questions) == 0 {
		return b.Finish()
	}
	q := req.Questions[0]
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	switch q.Type {
	case dnsmessage.TypeAAAA, dnsmessage.TypeA:
		want6 := q.Type == dnsmessage.TypeAAAA
		for _, ip := range addrs {
			if want6 != ip.Is6() {
				continue
			}
			if want6 {
				if err := b.AAAAResource(
					dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 5},
					dnsmessage.AAAAResource{AAAA: ip.As16()},
				); err != nil {
					return nil, err
				}
			} else {
				if err := b.AResource(
					dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 5},
					dnsmessage.AResource{A: ip.As4()},
				); err != nil {
					return nil, err
				}
			}
		}
	case dnsmessage.TypeSOA:
		if err := b.SOAResource(
			dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
			dnsmessage.SOAResource{NS: q.Name, MBox: tsMBox, Serial: 2023030600,
				Refresh: 120, Retry: 120, Expire: 120, MinTTL: 60},
		); err != nil {
			return nil, err
		}
	case dnsmessage.TypeNS:
		if err := b.NSResource(
			dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
			dnsmessage.NSResource{NS: tsMBox},
		); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// TODO just copied straight from natc.go
func proxyTCPConn(c net.Conn, dest string) {
	addrPortStr := c.LocalAddr().String()
	_, port, err := net.SplitHostPort(addrPortStr)
	if err != nil {
		// TODO tcpRoundRobinHandler?
		log.Printf("tcpRoundRobinHandler.Handle: bogus addrPort %q", addrPortStr)
		c.Close()
		return
	}

	p := &tcpproxy.Proxy{
		ListenFunc: func(net, laddr string) (net.Listener, error) {
			return netutil.NewOneConnListener(c, nil), nil
		},
	}
	p.AddRoute(addrPortStr, &tcpproxy.DialProxy{
		Addr: fmt.Sprintf("%s:%s", dest, port),
	})
	p.Start()
}

func (n *NatConnector) GetTCPHandlerForFlow(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
	nodeView, _, ok := n.whoIs("", src)
	if !ok {
		log.Printf("GetTCPHandlerForFlow: WhoIs invalid for: %v\n", src)
		return nil, false // TODO ? correct?
	}

	from := nodeView.ID()

	domain, err := n.ConsensusClient.LookupDomain(from, dst.Addr())
	if err != nil {
		log.Printf("GetTCPHandlerForFlow: LookupDomain error: %v\n", err)
		return nil, true // TODO true?
	}
	// TODO if domain is empty I guess we return intercept false?
	if domain == "" {
		return nil, false
	}

	return func(conn net.Conn) {
		proxyTCPConn(conn, domain)
	}, true
}

func (n *NatConnector) Stop() {
	fmt.Println("FRAN TODO Stop") // TODO fran
}

func (n *NatConnector) Start() {

}

func (n *NatConnector) StartConsensusMember(id string, clusterPeers tailcfg.ClusterInfo, varRoot string) {
	var leaderAddress string
	if clusterPeers.Leader.IsValid() {
		leaderAddress = clusterPeers.Leader.String()
	}
	// TODO something to do with channels to stop this?
	go func() {
		n.logf("Starting ippool consensus membership for natc")
		ippool.StartConsensusMember(id, clusterPeers.Addr.String(), leaderAddress, varRoot)
	}()
	n.ConsensusClient = ippool.NewConsensusClient(clusterPeers.Addr.String(), leaderAddress, n.logf)
}

func NewNatConnector(l logger.Logf, whoIs func(string, netip.AddrPort) (tailcfg.NodeView, tailcfg.UserProfile, bool)) NatConnector {
	return NatConnector{logf: l, whoIs: whoIs}
}
