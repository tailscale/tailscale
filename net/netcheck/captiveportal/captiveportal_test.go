// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package captiveportal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

func TestCheck(t *testing.T) {
	ctx := context.Background()
	dm, err := prodDERPMap(ctx, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	portal, err := Check(ctx, t.Logf, dm, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("captive portal: %v", portal)
}

func prodDERPMap(ctx context.Context, httpc *http.Client) (*tailcfg.DERPMap, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", ipn.DefaultControlURL+"/derpmap/default", nil)
	if err != nil {
		return nil, fmt.Errorf("create prodDERPMap request: %w", err)
	}
	res, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch prodDERPMap failed: %w", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("fetch prodDERPMap failed: %w", err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("fetch prodDERPMap: %v: %s", res.Status, b)
	}
	var derpMap tailcfg.DERPMap
	if err = json.Unmarshal(b, &derpMap); err != nil {
		return nil, fmt.Errorf("fetch prodDERPMap: %w", err)
	}
	return &derpMap, nil
}
