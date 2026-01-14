// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_aws

// Package awsparamstore registers support for fetching secret values from AWS
// Parameter Store.
package awsparamstore

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"tailscale.com/feature"
	"tailscale.com/internal/client/tailscale"
)

func init() {
	feature.Register("awsparamstore")
	tailscale.HookResolveValueFromParameterStore.Set(ResolveValue)
}

// parseARN parses and verifies that the input string is an
// ARN for AWS Parameter Store, returning the region and parameter name if so.
//
// If the input is not a valid Parameter Store ARN, it returns ok==false.
func parseARN(s string) (region, parameterName string, ok bool) {
	parsed, err := arn.Parse(s)
	if err != nil {
		return "", "", false
	}

	if parsed.Service != "ssm" {
		return "", "", false
	}
	parameterName, ok = strings.CutPrefix(parsed.Resource, "parameter/")
	if !ok {
		return "", "", false
	}

	// NOTE: parameter names must have a leading slash
	return parsed.Region, "/" + parameterName, true
}

// ResolveValue fetches a value from AWS Parameter Store if the input
// looks like an SSM ARN (e.g., arn:aws:ssm:us-east-1:123456789012:parameter/my-secret).
//
// If the input is not a Parameter Store ARN, it returns the value unchanged.
//
// If the input is a Parameter Store ARN and fetching the parameter fails, it
// returns an error.
func ResolveValue(ctx context.Context, valueOrARN string) (string, error) {
	// If it doesn't look like an ARN, return as-is
	region, parameterName, ok := parseARN(valueOrARN)
	if !ok {
		return valueOrARN, nil
	}

	// Load AWS config with the region from the ARN
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return "", fmt.Errorf("loading AWS config in region %q: %w", region, err)
	}

	// Create SSM client and fetch the parameter
	client := ssm.NewFromConfig(cfg)
	output, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		// The parameter to fetch.
		Name: aws.String(parameterName),

		// If the parameter is a SecureString, decrypt it.
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("getting SSM parameter %q: %w", parameterName, err)
	}

	if output.Parameter == nil || output.Parameter.Value == nil {
		return "", fmt.Errorf("SSM parameter %q has no value", parameterName)
	}

	return strings.TrimSpace(*output.Parameter.Value), nil
}
