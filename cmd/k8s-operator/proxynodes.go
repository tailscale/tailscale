package main

import (
	"log"
	"net/netip"
	"os"
	"strconv"
)

// TODO: probably remove this file
func proxycidr() {
	clusterDomain := os.Getenv("TS_CLUSTER_DOMAIN")
	if clusterDomain == "" {
		log.Fatal("TS_CLUSTER_DOMAIN must be set")
	}
	// TODO: check if domain already exists for a different CIDR; if so make <cluster-domain>-<n>

	// Allocate /24 and set /1 to resolve DNS for this subdomain?
	serviceCIDR := os.Getenv("TS_SERVICE_CIDR")
	if serviceCIDR == "" {
		log.Fatal("TS_SERVICE_CIDR must be set")
	}
	clusterSize := os.Getenv("TS_CLUSTER_SIZE")
	if clusterSize == "" {
		log.Fatal("TS_CLUSTER_SIZE must be set")
	}

	// create clusterSize proxies, each advertizes /24
	nProxies, err := strconv.Atoi(clusterSize)
	if err != nil {
		log.Fatalf("%s can not be converted to int: %v", clusterSize, err)
	}
	for range nProxies - 1 {
	}
}

func ensureProxyExists(n int) {
	const (
		labelserviceClass = "tailscale.com/service-class"
		labelProxyID      = "tailscale.com/proxy-id"
	)

}

type service struct {
	ip         netip.Addr
	domainName string
}

type dnsConfig struct {
	dnsNamesToIPs map[string][]netip.Addr
}
