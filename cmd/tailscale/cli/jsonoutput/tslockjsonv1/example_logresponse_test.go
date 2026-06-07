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

func ExampleLogResponse() {
	cmd := exec.Command("tailscale", "lock", "log", "--json")
	out, err := cmd.Output()
	if err != nil {
		if err, ok := errors.AsType[*exec.ExitError](err); ok {
			fmt.Fprintf(os.Stderr, "%s", err.Stderr)
		}
		panic(err)
	}

	var logs tslockjsonv1.LogResponse
	if err := json.Unmarshal(out, &logs); err != nil {
		panic(err)
	}
	for _, msg := range logs.Messages {
		fmt.Printf("{kind: %s, key id: %s, key: %+v}\n", msg.AUM.MessageKind, msg.AUM.KeyID, msg.AUM.Key)
	}
}
