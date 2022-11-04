// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package awsstore

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"tailscale.com/ipn"
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
	store := &awsStore{
		ssmARN: arn.ARN{
			Service:   "ssm",
			Region:    "eu-west-1",
			AccountID: "123456789",
			Resource:  "parameter/foo",
		},
	}
	want := "awsStore(\"arn::ssm:eu-west-1:123456789:parameter/foo\")"
	if got := store.String(); got != want {
		t.Errorf("AWSStore.String = %q; want %q", got, want)
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

	s, err := newStore(storeParameterARN.String(), mc)
	if err != nil {
		t.Fatalf("creating aws store failed: %v", err)
	}
	testStoreSemantics(t, s)

	// Build a brand new file store and check that both IDs written
	// above are still there.
	s2, err := newStore(storeParameterARN.String(), mc)
	if err != nil {
		t.Fatalf("creating second aws store failed: %v", err)
	}
	store2 := s.(*awsStore)

	// This is specific to the test, with the non-mocked API, LoadState() should
	// have been already called and successful as no err is returned from NewAWSStore()
	s2.(*awsStore).LoadState()

	expected := map[ipn.StateKey]string{
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

func testStoreSemantics(t *testing.T, store ipn.StateStore) {
	t.Helper()

	tests := []struct {
		// if true, data is data to write. If false, data is expected
		// output of read.
		write bool
		id    ipn.StateKey
		data  string
		// If write=false, true if we expect a not-exist error.
		notExists bool
	}{
		{
			id:        "foo",
			notExists: true,
		},
		{
			write: true,
			id:    "foo",
			data:  "bar",
		},
		{
			id:   "foo",
			data: "bar",
		},
		{
			id:        "baz",
			notExists: true,
		},
		{
			write: true,
			id:    "baz",
			data:  "quux",
		},
		{
			id:   "foo",
			data: "bar",
		},
		{
			id:   "baz",
			data: "quux",
		},
	}

	for _, test := range tests {
		if test.write {
			if err := store.WriteState(test.id, []byte(test.data)); err != nil {
				t.Errorf("writing %q to %q: %v", test.data, test.id, err)
			}
		} else {
			bs, err := store.ReadState(test.id)
			if err != nil {
				if test.notExists && err == ipn.ErrStateNotExist {
					continue
				}
				t.Errorf("reading %q: %v", test.id, err)
				continue
			}
			if string(bs) != test.data {
				t.Errorf("reading %q: got %q, want %q", test.id, string(bs), test.data)
			}
		}
	}
}
