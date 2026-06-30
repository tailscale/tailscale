// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonoutput_test

import (
	"encoding/json"
	"fmt"

	"tailscale.com/cmd/tailscale/cli/jsonoutput"
)

type Hello struct {
	jsonoutput.ResponseEnvelope
	Greeting string
}

func ExampleResponseEnvelope() {
	hi := Hello{
		ResponseEnvelope: jsonoutput.ResponseEnvelope{SchemaVersion: "1"},
		Greeting:         "Hello, world",
	}
	out, err := json.MarshalIndent(hi, "", "    ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", out)
	// Output:
	// {
	//     "SchemaVersion": "1",
	//     "Greeting": "Hello, world"
	// }
}
