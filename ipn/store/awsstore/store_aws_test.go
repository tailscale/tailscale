// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_aws

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

	opts := storeOptions{
		kmsKey: "arn:aws:kms:eu-west-1:123456789:key/MyCustomKey",
	}

	s, err := newStore(storeParameterARN.String(), opts, mc)
	if err != nil {
		t.Fatalf("creating aws store failed: %v", err)
	}
	testStoreSemantics(t, s)

	// Build a brand new file store and check that both IDs written
	// above are still there.
	s2, err := newStore(storeParameterARN.String(), opts, mc)
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

func TestParseARNAndOpts(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		wantARN string
		wantKey string
	}{
		{
			name:    "no-key",
			arg:     "arn:aws:ssm:us-east-1:123456789012:parameter/myTailscaleParam",
			wantARN: "arn:aws:ssm:us-east-1:123456789012:parameter/myTailscaleParam",
		},
		{
			name:    "custom-key",
			arg:     "arn:aws:ssm:us-east-1:123456789012:parameter/myTailscaleParam?kmsKey=alias/MyCustomKey",
			wantARN: "arn:aws:ssm:us-east-1:123456789012:parameter/myTailscaleParam",
			wantKey: "alias/MyCustomKey",
		},
		{
			name:    "bare-name",
			arg:     "arn:aws:ssm:us-east-1:123456789012:parameter/myTailscaleParam?kmsKey=Bare",
			wantARN: "arn:aws:ssm:us-east-1:123456789012:parameter/myTailscaleParam",
			wantKey: "alias/Bare",
		},
		{
			name:    "arn-arg",
			arg:     "arn:aws:ssm:us-east-1:123456789012:parameter/myTailscaleParam?kmsKey=arn:foo",
			wantARN: "arn:aws:ssm:us-east-1:123456789012:parameter/myTailscaleParam",
			wantKey: "arn:foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arn, opts, err := ParseARNAndOpts(tt.arg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if arn != tt.wantARN {
				t.Errorf("ARN = %q; want %q", arn, tt.wantARN)
			}
			var got storeOptions
			for _, opt := range opts {
				opt(&got)
			}
			if got.kmsKey != tt.wantKey {
				t.Errorf("kmsKey = %q; want %q", got.kmsKey, tt.wantKey)
			}
		})
	}
}
