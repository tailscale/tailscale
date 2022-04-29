// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var idTokenCmd = &ffcli.Command{
	Name:       "id-token",
	ShortUsage: "id-token <aud>",
	ShortHelp:  "fetch an OIDC id-token for the Tailscale machine",
	Exec:       runIDToken,
}

func runIDToken(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: id-token <aud>")
	}

	tr, err := localClient.IDToken(ctx, args[0])
	if err != nil {
		return err
	}

	fmt.Println(tr.IDToken)
	return nil
}
