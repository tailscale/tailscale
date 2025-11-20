// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_aws

// Package awsstore contains an ipn.StateStore implementation using AWS SSM.
package awsstore

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/logger"
)

func init() {
	store.Register("arn:", func(logf logger.Logf, arg string) (ipn.StateStore, error) {
		ssmARN, opts, err := ParseARNAndOpts(arg)
		if err != nil {
			return nil, err
		}
		return New(logf, ssmARN, opts...)
	})
}

const (
	parameterNameRxStr = `^parameter(/.*)`
)

var parameterNameRx = regexp.MustCompile(parameterNameRxStr)

// Option defines a functional option type for configuring awsStore.
type Option func(*storeOptions)

// storeOptions holds optional settings for creating a new awsStore.
type storeOptions struct {
	kmsKey string
}

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

	// kmsKey is optional. If empty, the parameter is stored in plaintext.
	// If non-empty, the parameter is encrypted with this KMS key.
	kmsKey string

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
//
// If you want to specify an optional KMS key,
// pass one or more Option objects, e.g. awsstore.WithKeyID("alias/my-key").
func New(_ logger.Logf, ssmARN string, opts ...Option) (ipn.StateStore, error) {
	// Apply all options to an empty storeOptions
	var so storeOptions
	for _, opt := range opts {
		opt(&so)
	}

	return newStore(ssmARN, so, nil)
}

// WithKeyID sets the KMS key to be used for encryption. It can be
// a KeyID, an alias ("alias/my-key"), or a full ARN.
//
// If kmsKey is empty, the Option is a no-op.
func WithKeyID(kmsKey string) Option {
	return func(o *storeOptions) {
		o.kmsKey = kmsKey
	}
}

// ParseARNAndOpts parses an ARN and optional URL-encoded parameters
// from arg.
func ParseARNAndOpts(arg string) (ssmARN string, opts []Option, err error) {
	ssmARN = arg

	// Support optional ?url-encoded-parameters.
	if s, q, ok := strings.Cut(arg, "?"); ok {
		ssmARN = s
		q, err := url.ParseQuery(q)
		if err != nil {
			return "", nil, err
		}

		for k := range q {
			switch k {
			default:
				return "", nil, fmt.Errorf("unknown arn option parameter %q", k)
			case "kmsKey":
				// We allow an ARN, a key ID, or an alias name for kmsKeyID.
				// If it doesn't look like an ARN and doesn't have a '/',
				// prepend "alias/" for KMS alias references.
				kmsKey := q.Get(k)
				if kmsKey != "" &&
					!strings.Contains(kmsKey, "/") &&
					!strings.HasPrefix(kmsKey, "arn:") {
					kmsKey = "alias/" + kmsKey
				}
				if kmsKey != "" {
					opts = append(opts, WithKeyID(kmsKey))
				}
			}
		}
	}
	return ssmARN, opts, nil
}

// newStore is NewStore, but for tests. If client is non-nil, it's
// used instead of making one.
func newStore(ssmARN string, so storeOptions, client awsSSMClient) (ipn.StateStore, error) {
	s := &awsStore{
		ssmClient: client,
		kmsKey:    so.kmsKey,
	}

	var err error
	if s.ssmARN, err = arn.Parse(ssmARN); err != nil {
		return nil, fmt.Errorf("unable to parse the ARN correctly: %v", err)
	}
	if s.ssmARN.Service != "ssm" {
		return nil, fmt.Errorf("invalid service %q, expected 'ssm'", s.ssmARN.Service)
	}
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

	// Preload existing state, if any
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
	in := &ssm.PutParameterInput{
		Name:      aws.String(s.ParameterName()),
		Value:     aws.String(string(bs)),
		Overwrite: aws.Bool(true),
		Tier:      ssmTypes.ParameterTierIntelligentTiering,
		Type:      ssmTypes.ParameterTypeSecureString,
	}

	// If kmsKey is specified, encrypt with that key
	// NOTE: this input allows any alias, keyID or ARN
	// If this isn't specified, AWS will use the default KMS key
	if s.kmsKey != "" {
		in.KeyId = aws.String(s.kmsKey)
	}

	_, err = s.ssmClient.PutParameter(context.TODO(), in)
	return err
}
