package ippool

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tsconsensus"
	"tailscale.com/util/must"
)

func makeSetFromPrefix(pfx netip.Prefix) *netipx.IPSet {
	var ipsb netipx.IPSetBuilder
	ipsb.AddPrefix(pfx)
	return must.Get(ipsb.IPSet())
}

type FakeConsensus struct {
	ipp *ConsensusIPPool
}

func (c *FakeConsensus) ExecuteCommand(cmd tsconsensus.Command) (tsconsensus.CommandResult, error) {
	b, err := json.Marshal(cmd)
	if err != nil {
		return tsconsensus.CommandResult{}, err
	}
	result := c.ipp.Apply(&raft.Log{Data: b})
	return result.(tsconsensus.CommandResult), nil
}

func makePool(pfx netip.Prefix) *ConsensusIPPool {
	ipp := &ConsensusIPPool{
		IPSet: makeSetFromPrefix(pfx),
	}
	ipp.consensus = &FakeConsensus{ipp: ipp}
	return ipp
}

func TestConsensusIPForDomain(t *testing.T) {
	pfx := netip.MustParsePrefix("100.64.0.0/16")
	ipp := makePool(pfx)
	from := tailcfg.NodeID(1)

	a, err := ipp.IPForDomain(from, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !pfx.Contains(a) {
		t.Fatalf("expected %v to be in the prefix %v", a, pfx)
	}

	b, err := ipp.IPForDomain(from, "a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !pfx.Contains(b) {
		t.Fatalf("expected %v to be in the prefix %v", b, pfx)
	}
	if b == a {
		t.Fatalf("same address issued twice %v, %v", a, b)
	}

	c, err := ipp.IPForDomain(from, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c != a {
		t.Fatalf("expected %v to be remembered as the addr for example.com, but got %v", a, c)
	}
}

func TestConsensusPoolExhaustion(t *testing.T) {
	ipp := makePool(netip.MustParsePrefix("100.64.0.0/31"))
	from := tailcfg.NodeID(1)

	subdomains := []string{"a", "b", "c"}
	for i, sd := range subdomains {
		_, err := ipp.IPForDomain(from, fmt.Sprintf("%s.example.com", sd))
		if i < 2 && err != nil {
			t.Fatal(err)
		}
		expected := "ip pool exhausted"
		if i == 2 && err.Error() != expected {
			t.Fatalf("expected error to be '%s', got '%s'", expected, err.Error())
		}
	}
}

func TestConsensusPoolExpiry(t *testing.T) {
	ipp := makePool(netip.MustParsePrefix("100.64.0.0/31"))
	firstIP := netip.MustParseAddr("100.64.0.0")
	secondIP := netip.MustParseAddr("100.64.0.1")
	timeOfUse := time.Now()
	beforeTimeOfUse := timeOfUse.Add(-2 * time.Hour)
	afterTimeOfUse := timeOfUse.Add(2 * time.Hour)
	from := tailcfg.NodeID(1)

	// the pool is unused, we get an address, and it's marked as being used at timeOfUse
	aAddr, err := ipp.applyCheckoutAddr(from, "a.example.com", timeOfUse, timeOfUse)
	if err != nil {
		t.Fatal(err)
	}
	if aAddr.Compare(firstIP) != 0 {
		t.Fatalf("expected %s, got %s", firstIP, aAddr)
	}
	d, ok := ipp.DomainForIP(from, firstIP, timeOfUse)
	if !ok {
		t.Fatal("expected addr to be found")
	}
	if d != "a.example.com" {
		t.Fatalf("expected aAddr to look up to a.example.com, got: %s", d)
	}

	// the time before which we will reuse addresses is prior to timeOfUse, so no reuse
	bAddr, err := ipp.applyCheckoutAddr(from, "b.example.com", beforeTimeOfUse, timeOfUse)
	if err != nil {
		t.Fatal(err)
	}
	if bAddr.Compare(secondIP) != 0 {
		t.Fatalf("expected %s, got %s", secondIP, bAddr)
	}

	// the time before which we will reuse addresses is after timeOfUse, so reuse addresses that were marked as used at timeOfUse.
	cAddr, err := ipp.applyCheckoutAddr(from, "c.example.com", afterTimeOfUse, timeOfUse)
	if err != nil {
		t.Fatal(err)
	}
	if cAddr.Compare(firstIP) != 0 {
		t.Fatalf("expected %s, got %s", firstIP, cAddr)
	}
	d, ok = ipp.DomainForIP(from, firstIP, timeOfUse)
	if !ok {
		t.Fatal("expected addr to be found")
	}
	if d != "c.example.com" {
		t.Fatalf("expected firstIP to look up to c.example.com, got: %s", d)
	}

	// the addr remains associated with c.example.com
	cAddrAgain, err := ipp.applyCheckoutAddr(from, "c.example.com", beforeTimeOfUse, timeOfUse)
	if err != nil {
		t.Fatal(err)
	}
	if cAddrAgain.Compare(cAddr) != 0 {
		t.Fatalf("expected cAddrAgain to be cAddr, but they are different. cAddrAgain=%s cAddr=%s", cAddrAgain, cAddr)
	}
	d, ok = ipp.DomainForIP(from, firstIP, timeOfUse)
	if !ok {
		t.Fatal("expected addr to be found")
	}
	if d != "c.example.com" {
		t.Fatalf("expected firstIP to look up to c.example.com, got: %s", d)
	}
}

func TestConsensusDomainForIP(t *testing.T) {
	ipp := makePool(netip.MustParsePrefix("100.64.0.0/16"))
	from := tailcfg.NodeID(1)
	domain := "example.com"
	now := time.Now()

	d, ok := ipp.DomainForIP(from, netip.MustParseAddr("100.64.0.1"), now)
	if d != "" {
		t.Fatalf("expected an empty string if the addr is not found but got %s", d)
	}
	if ok {
		t.Fatalf("expected domain to not be found for IP, as it has never been looked up")
	}
	a, err := ipp.IPForDomain(from, domain)
	if err != nil {
		t.Fatal(err)
	}
	d2, ok := ipp.DomainForIP(from, a, now)
	if d2 != domain {
		t.Fatalf("expected %s but got %s", domain, d2)
	}
	if !ok {
		t.Fatalf("expected domain to be found for IP that was handed out for it")
	}
}
