// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_aws

// Package awsstore contains an ipn.StateStore implementation using AWS SSM.
package awsstore

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/logger"
)

const (
	parameterNameRxStr = `^parameter(/.*)`
)

var parameterNameRx = regexp.MustCompile(parameterNameRxStr)

// awsSSMClient is an interface allowing us to mock the couple of
// API calls we are leveraging with the AWSStore provider
type awsSSMClient interface {
	GetParameter(ctx context.Context,
		params *ssm.GetParameterInput,
		optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)

	PutParameter(ctx context.Context,
		params *ssm.PutParameterInput,
		optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// store is a store which leverages AWS SSM parameter store
// to persist the state
type awsStore struct {
	ssmClient awsSSMClient
	ssmARN    arn.ARN

	memory mem.Store
}

// New returns a new ipn.StateStore using the AWS SSM storage
// location given by ssmARN.
//
// Note that we store the entire store in a single parameter
// key, therefore if the state is above 8kb, it can cause
// Tailscaled to only only store new state in-memory and
// restarting Tailscaled can fail until you delete your state
// from the AWS Parameter Store.
func New(_ logger.Logf, ssmARN string) (ipn.StateStore, error) {
	return newStore(ssmARN, nil)
}

// newStore is NewStore, but for tests. If client is non-nil, it's
// used instead of making one.
func newStore(ssmARN string, client awsSSMClient) (ipn.StateStore, error) {
	s := &awsStore{
		ssmClient: client,
	}

	var err error

	// Parse the ARN
	if s.ssmARN, err = arn.Parse(ssmARN); err != nil {
		return nil, fmt.Errorf("unable to parse the ARN correctly: %v", err)
	}

	// Validate the ARN corresponds to the SSM service
	if s.ssmARN.Service != "ssm" {
		return nil, fmt.Errorf("invalid service %q, expected 'ssm'", s.ssmARN.Service)
	}

	// Validate the ARN corresponds to a parameter store resource
	if !parameterNameRx.MatchString(s.ssmARN.Resource) {
		return nil, fmt.Errorf("invalid resource %q, expected to match %v", s.ssmARN.Resource, parameterNameRxStr)
	}

	if s.ssmClient == nil {
		var cfg aws.Config
		if cfg, err = config.LoadDefaultConfig(
			context.TODO(),
			config.WithRegion(s.ssmARN.Region),
		); err != nil {
			return nil, err
		}
		s.ssmClient = ssm.NewFromConfig(cfg)
	}

	// Hydrate cache with the potentially current state
	if err := s.LoadState(); err != nil {
		return nil, err
	}
	return s, nil

}

// LoadState attempts to read the state from AWS SSM parameter store key.
func (s *awsStore) LoadState() error {
	param, err := s.ssmClient.GetParameter(
		context.TODO(),
		&ssm.GetParameterInput{
			Name:           aws.String(s.ParameterName()),
			WithDecryption: aws.Bool(true),
		},
	)

	if err != nil {
		var pnf *ssmTypes.ParameterNotFound
		if errors.As(err, &pnf) {
			// Create the parameter as it does not exist yet
			// and return directly as it is defacto empty
			return s.persistState()
		}
		return err
	}

	// Load the content in-memory
	return s.memory.LoadFromJSON([]byte(*param.Parameter.Value))
}

// ParameterName returns the parameter name extracted from
// the provided ARN
func (s *awsStore) ParameterName() (name string) {
	values := parameterNameRx.FindStringSubmatch(s.ssmARN.Resource)
	if len(values) == 2 {
		name = values[1]
	}
	return
}

// String returns the awsStore and the ARN of the SSM parameter store
// configured to store the state
func (s *awsStore) String() string { return fmt.Sprintf("awsStore(%q)", s.ssmARN.String()) }

// ReadState implements the Store interface.
func (s *awsStore) ReadState(id ipn.StateKey) (bs []byte, err error) {
	return s.memory.ReadState(id)
}

// WriteState implements the Store interface.
func (s *awsStore) WriteState(id ipn.StateKey, bs []byte) (err error) {
	// Write the state in-memory
	if err = s.memory.WriteState(id, bs); err != nil {
		return
	}

	// Persist the state in AWS SSM parameter store
	return s.persistState()
}

// PersistState saves the states into the AWS SSM parameter store
func (s *awsStore) persistState() error {
	// Generate JSON from in-memory cache
	bs, err := s.memory.ExportToJSON()
	if err != nil {
		return err
	}

	// Store in AWS SSM parameter store.
	//
	// We use intelligent tiering so that when the state is below 4kb, it uses Standard tiering
	// which is free. However, if it exceeds 4kb it switches the parameter to advanced tiering
	// doubling the capacity to 8kb per the following docs:
	// https://aws.amazon.com/about-aws/whats-new/2019/08/aws-systems-manager-parameter-store-announces-intelligent-tiering-to-enable-automatic-parameter-tier-selection/
	_, err = s.ssmClient.PutParameter(
		context.TODO(),
		&ssm.PutParameterInput{
			Name:      aws.String(s.ParameterName()),
			Value:     aws.String(string(bs)),
			Overwrite: aws.Bool(true),
			Tier:      ssmTypes.ParameterTierIntelligentTiering,
			Type:      ssmTypes.ParameterTypeSecureString,
		},
	)
	return err
}
