// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonoutput_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"tailscale.com/cmd/tailscale/cli/jsonoutput"
)

func ExampleDNSQueryResult() {
	cmd := exec.Command("tailscale", "dns", "query", "--json", "hello.ts.net")
	out, err := cmd.Output()
	if err != nil {
		if err, ok := errors.AsType[*exec.ExitError](err); ok {
			fmt.Fprintf(os.Stderr, "%s", err.Stderr)
		}
		panic(err)
	}

	var dnsQuery jsonoutput.DNSQueryResult
	if err := json.Unmarshal(out, &dnsQuery); err != nil {
		panic(err)
	}
	fmt.Printf("{type: %s, name: %q}\n", dnsQuery.QueryType, dnsQuery.Name)
}
