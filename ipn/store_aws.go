// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !darwin

package ipn

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
)

const (
	parameterNameRegexp string = `^parameter/(.*)`
)

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

// AWSStore is a store which leverages AWS SSM parameter store
// to persist the state
type AWSStore struct {
	ssmClient awsSSMClient
	ssmARN    arn.ARN

	memory *MemoryStore
}

// NewAWSStore returns a new AWSStore with an hydrated cache
func NewAWSStore(ssmARN string) (s *AWSStore, err error) {
	s = &AWSStore{
		memory: &MemoryStore{},
	}

	// Parse the ARN
	if s.ssmARN, err = arn.Parse(ssmARN); err != nil {
		err = fmt.Errorf("unable to parse the ARN correctly: %v", err)
		return
	}

	// Validate the ARN corresponds to the SSM service
	if s.ssmARN.Service != "ssm" {
		err = fmt.Errorf("invalid service '%s', expected 'ssm'", s.ssmARN.Service)
		return
	}

	// Validate the ARN corresponds to a parameter store resource
	re := regexp.MustCompile(parameterNameRegexp)
	if !re.MatchString(s.ssmARN.Resource) {
		err = fmt.Errorf("invalid resource '%s', expected '%s'", s.ssmARN.Resource, parameterNameRegexp)
		return
	}

	var cfg aws.Config
	if cfg, err = config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion(s.ssmARN.Region),
	); err != nil {
		return
	}

	s.ssmClient = ssm.NewFromConfig(cfg)

	// Hydrate cache with the potentially current state
	err = s.LoadState()
	return
}

// LoadState attempts to read the state from AWS SSM parameter store key.
func (s *AWSStore) LoadState() (err error) {
	var param *ssm.GetParameterOutput
	param, err = s.ssmClient.GetParameter(
		context.TODO(),
		&ssm.GetParameterInput{
			Name:           aws.String(s.ParameterName()),
			WithDecryption: true,
		},
	)

	if err != nil {
		var pnf *ssmTypes.ParameterNotFound
		if errors.As(err, &pnf) {
			// Create the parameter as it does not exist yet
			// and return directly as it is defacto empty
			return s.PersistState()
		}
	}

	// Load the content in-memory
	return s.memory.LoadFromJSON([]byte(*param.Parameter.Value))
}

// ParameterName returns the parameter name extracted from
// the provided ARN
func (s *AWSStore) ParameterName() (name string) {
	re := regexp.MustCompile(parameterNameRegexp)
	values := re.FindStringSubmatch(s.ssmARN.Resource)
	if len(values) == 2 {
		name = values[1]
	}
	return
}

// String returns the AWSStore and the ARN of the SSM parameter store
// configured to store the state
func (s *AWSStore) String() string { return fmt.Sprintf("AWSStore(%q)", s.ssmARN.String()) }

// ReadState implements the Store interface.
func (s *AWSStore) ReadState(id StateKey) (bs []byte, err error) {
	return s.memory.ReadState(id)
}

// WriteState implements the Store interface.
func (s *AWSStore) WriteState(id StateKey, bs []byte) (err error) {
	// Write the state in-memory
	if err = s.memory.WriteState(id, bs); err != nil {
		return
	}

	// Persist the state in AWS SSM parameter store
	return s.PersistState()
}

// PersistState saves the states into the AWS SSM parameter store
func (s *AWSStore) PersistState() (err error) {
	// Generate JSON from in-memory cache
	var bs []byte
	bs, err = s.memory.ExportToJSON()
	if err != nil {
		return
	}

	// Store in AWS SSM parameter store
	_, err = s.ssmClient.PutParameter(
		context.TODO(),
		&ssm.PutParameterInput{
			Name:      aws.String(s.ParameterName()),
			Value:     aws.String(string(bs)),
			Overwrite: true,
			Tier:      ssmTypes.ParameterTierStandard,
			Type:      ssmTypes.ParameterTypeSecureString,
		},
	)
	return
}
