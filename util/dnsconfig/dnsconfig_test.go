package dnsconfig

import "testing"

func TestGet(t *testing.T) {
	config, err := Get()
	if err != nil {
		t.Fatal(err)
	}

	if len(config.Resolvers) < 1 {
		t.Fatal("wanted at least one resolver")
	}

	// Sensibility check: do we have at least one nameserver?
	var nameservers int
	for _, resolver := range config.Resolvers {
		nameservers += len(resolver.Nameservers)
	}
	for _, resolver := range config.ScopedResolvers {
		nameservers += len(resolver.Nameservers)
	}
	for _, resolver := range config.ServiceSpecificResolvers {
		nameservers += len(resolver.Nameservers)
	}

	if nameservers == 0 {
		t.Fatal("wanted at least one nameserver, got 0")
	}
}
