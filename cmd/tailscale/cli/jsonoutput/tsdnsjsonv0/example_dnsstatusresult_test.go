// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsdnsjsonv0_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"tailscale.com/cmd/tailscale/cli/jsonoutput/tsdnsjsonv0"
)

func ExampleStatusResponse() {
	cmd := exec.Command("tailscale", "dns", "status", "--json")
	out, err := cmd.Output()
	if err != nil {
		if err, ok := errors.AsType[*exec.ExitError](err); ok {
			fmt.Fprintf(os.Stderr, "%s", err.Stderr)
		}
		panic(err)
	}

	var resp tsdnsjsonv0.StatusResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		panic(err)
	}
	fmt.Printf("{accept-dns: %t, resolvers: %q}\n", resp.TailscaleDNS, resp.Resolvers)
}
