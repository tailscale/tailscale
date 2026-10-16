// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conffile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/omit"
)

// metadataTimeout is the maximum time to wait for each request to the VM
// metadata service. The service is link-local, so if it does not answer
// quickly (e.g. on a host that is not a cloud VM) it is not going to.
var metadataTimeout = 5 * time.Second

func getEC2MetadataToken() (string, error) {
	if omit.AWS {
		return "", omit.Err
	}
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "PUT", "http://169.254.169.254/latest/api/token", nil)
	req.Header.Add("X-aws-ec2-metadata-token-ttl-seconds", "300")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get metadata token: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", fmt.Errorf("failed to get metadata token: %v", res.Status)
	}
	all, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata token: %w", err)
	}
	return strings.TrimSpace(string(all)), nil
}

func readVMUserData() ([]byte, error) {
	if !buildfeatures.HasAWS {
		return nil, feature.ErrUnavailable
	}
	// TODO(bradfitz): support GCP, Azure, Proxmox/cloud-init
	// (NoCloud/ConfigDrive ISO), etc.

	if omit.AWS {
		return nil, omit.Err
	}
	token, tokErr := getEC2MetadataToken()
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/latest/user-data", nil)
	req.Header.Add("X-aws-ec2-metadata-token", token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		if tokErr != nil {
			return nil, fmt.Errorf("failed to get VM user data: %v; also failed to get metadata token: %v", res.Status, tokErr)
		}
		return nil, errors.New(res.Status)
	}
	return io.ReadAll(res.Body)
}
