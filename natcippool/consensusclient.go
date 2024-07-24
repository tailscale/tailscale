package ippool

import (
	"context"
	"net/netip"
	"strings"

	"github.com/redis/go-redis/v9"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// ConsensusClient wraps a redis client (because that's what uhaha supports out of the box) with
// functions for our specific use and retry logic to find the leader if the leader goes away.
type ConsensusClient struct {
	MyAddr     string
	LeaderAddr string
	logf       logger.Logf
	rdb        *redis.Client
}

func NewConsensusClient(addr, joinAddr string, logf logger.Logf) *ConsensusClient {
	cc := ConsensusClient{
		MyAddr: addr,
		logf:   logf,
	}
	if joinAddr == "" {
		// initially i am the leader
		cc.newRedisClient(addr)
	} else {
		// initially i am a follower
		cc.newRedisClient(joinAddr)
	}
	return &cc
}

func (f *ConsensusClient) newRedisClient(addr string) {
	f.LeaderAddr = addr
	f.rdb = redis.NewClient(&redis.Options{
		Addr:     f.LeaderAddr,
		Password: "", // no password set
		DB:       0,  // use default DB
	})
}

func newAddrFromErr(err error) (string, bool) {
	//https://github.com/tidwall/uhaha/blob/master/uhaha.go#L906C1-L913C8
	if strings.HasPrefix(err.Error(), "MOVED ") {
		parts := strings.Split(err.Error(), " ")
		if len(parts) == 3 {
			return parts[2], true
		}
	}
	return "", false
}

func (f *ConsensusClient) followMyLeader(callback func() error) error {
	var err error
	var count int
	for (count == 0 || err != nil) && count < 10 {
		err = callback()
		if err != nil {
			// assume the err is related to the leader being gone and try to find the new leader
			newAddr, ok := newAddrFromErr(err)
			if !ok {
				// if it's not a moved error then maybe I'm the leader, or at least I'll be able to reply with a moved err
				newAddr = f.MyAddr
			}
			f.logf("ConsensusClient error, trying new addr: %s", newAddr)
			f.newRedisClient(newAddr)
		}
		count++
	}
	if err != nil {
		f.logf("ConsensusClient done with retries unsuccessfully: %v", err)
	}
	return err
}

// TODO this should return a netip.Addr not a string
func (f *ConsensusClient) CheckOut(nid tailcfg.NodeID, domain string) (string, error) {
	var s string
	err := f.followMyLeader(func() error {
		var innerErr error
		s, innerErr = f.rdb.Do(context.Background(), "IPCHECKOUT", int(nid), domain).Text()
		return innerErr
	})
	return s, err
}

func (f *ConsensusClient) LookupDomain(nid tailcfg.NodeID, addr netip.Addr) (string, error) {
	var s string
	err := f.followMyLeader(func() error {
		var innerErr error
		s, innerErr = f.rdb.Do(context.Background(), "DOMAINLOOKUP", int(nid), addr.String()).Text()
		return innerErr
	})
	return s, err
}

//func (f *ConsensusClient) CheckIn(i int) error {
//err := f.followMyLeader(func() error {
//_, innerErr := f.rdb.Do(context.Background(), "IPCHECKIN", i).Result()
//return innerErr
//})
//return err
//}
