// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tslockjsonv1_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"tailscale.com/cmd/tailscale/cli/jsonoutput/tslockjsonv1"
)

func ExampleStatusResponse() {
	cmd := exec.Command("tailscale", "lock", "status", "--json")
	out, err := cmd.Output()
	if err != nil {
		if err, ok := errors.AsType[*exec.ExitError](err); ok {
			fmt.Fprintf(os.Stderr, "%s", err.Stderr)
		}
		panic(err)
	}

	var status tslockjsonv1.StatusResponse
	if err := json.Unmarshal(out, &status); err != nil {
		panic(err)
	}
	fmt.Printf("{enabled: %t, public key: %s, node key: %s}\n", status.Enabled, status.PublicKey, status.NodeKey)
}
