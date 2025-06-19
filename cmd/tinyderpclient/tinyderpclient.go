package main

import (
	"context"
	"encoding/json"
	"log"
	"maps"
	"net/http"
	"slices"

	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func main() {
	dm := &tailcfg.DERPMap{}
	res, err := http.Get("https://controlplane.tailscale.com/derpmap/default")
	if err != nil {
		log.Fatalf("fetching DERPMap: %v", err)
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(dm); err != nil {
		log.Fatalf("decoding DERPMap: %v", err)
	}

	region := slices.Sorted(maps.Keys(dm.Regions))[0]

	netMon := netmon.NewStatic()
	rc := derphttp.NewRegionClient(key.NewNode(), log.Printf, netMon, func() *tailcfg.DERPRegion {
		return dm.Regions[region]
	})
	defer rc.Close()

	if err := rc.Connect(context.Background()); err != nil {
		log.Fatalf("rc.Connect: %v", err)
	}
}
