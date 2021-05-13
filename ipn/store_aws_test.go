// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !darwin

package ipn

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"tailscale.com/tstest"
)

type mockedAWSSSMClient struct {
	value string
}

func (sp *mockedAWSSSMClient) GetParameter(_ context.Context, input *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	output := new(ssm.GetParameterOutput)
	if sp.value == "" {
		return output, &ssmTypes.ParameterNotFound{}
	}

	output.Parameter = &ssmTypes.Parameter{
		Value: aws.String(sp.value),
	}

	return output, nil
}

func (sp *mockedAWSSSMClient) PutParameter(_ context.Context, input *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	sp.value = *input.Value
	return new(ssm.PutParameterOutput), nil
}

func TestAWSStoreString(t *testing.T) {
	store := &AWSStore{
		ssmARN: arn.ARN{
			Service:   "ssm",
			Region:    "eu-west-1",
			AccountID: "123456789",
			Resource:  "parameter/foo",
		},
	}
	expected := "AWSStore(\"arn::ssm:eu-west-1:123456789:parameter/foo\")"
	if store.String() != expected {
		t.Errorf("AWSStore.String(): got %q, want %q", store.String(), expected)
	}
}

func TestNewAWSStore(t *testing.T) {
	tstest.PanicOnLog()

	mc := &mockedAWSSSMClient{}
	storeParameterARN := arn.ARN{
		Service:   "ssm",
		Region:    "eu-west-1",
		AccountID: "123456789",
		Resource:  "parameter/foo",
	}

	store, err := NewAWSStore(storeParameterARN.String())
	if err != nil {
		t.Fatalf("creating aws store failed: %v", err)
	}

	store.ssmClient = mc
	testStoreSemantics(t, store)

	// Build a brand new file store and check that both IDs written
	// above are still there.
	store2, err := NewAWSStore(storeParameterARN.String())
	if err != nil {
		t.Fatalf("creating second aws store failed: %v", err)
	}

	// This is specific to the test, with the non-mocked API, LoadState() should
	// have been already called and sucessful as no err is returned from NewAWSStore()
	store2.ssmClient = mc
	store2.LoadState()

	expected := map[StateKey]string{
		"foo": "bar",
		"baz": "quux",
	}
	for id, want := range expected {
		bs, err := store2.ReadState(id)
		if err != nil {
			t.Errorf("reading %q (2nd store): %v", id, err)
		}
		if string(bs) != want {
			t.Errorf("reading %q (2nd store): got %q, want %q", id, string(bs), want)
		}
	}
}
