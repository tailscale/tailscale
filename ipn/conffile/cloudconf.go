// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package conffile

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/omit"
)

func getEC2MetadataToken() (string, error) {
	if omit.AWS {
		return "", omit.Err
	}
	req, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
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
	req, _ := http.NewRequest("GET", "http://169.254.169.254/latest/user-data", nil)
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
