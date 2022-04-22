package gcpstore

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/googleapi"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/storetest"
	"tailscale.com/tstest"
)

type mockedGCPSecretManagerClient struct {
	exists          bool
	value           []byte
	version         int
	deletedVersions map[int]bool
}

func newMockedGCPSecretManagerClient() *mockedGCPSecretManagerClient {
	return &mockedGCPSecretManagerClient{
		exists:          false,
		version:         0,
		deletedVersions: make(map[int]bool),
	}
}

func (m *mockedGCPSecretManagerClient) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	if !m.exists {
		return nil, &googleapi.Error{Code: http.StatusNotFound}
	}
	version := versionStringFromSecretID(req.Name)
	if version != "latest" {
		return nil, &googleapi.Error{Code: http.StatusInternalServerError}
	}
	return &secretmanagerpb.AccessSecretVersionResponse{
		Name: req.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: m.value,
		},
	}, nil
}

func (m *mockedGCPSecretManagerClient) CreateSecret(_ context.Context, req *secretmanagerpb.CreateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	m.exists = true
	req.Secret.Name = req.SecretId
	return req.Secret, nil
}

func (m *mockedGCPSecretManagerClient) AddSecretVersion(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	if !m.exists {
		return nil, &googleapi.Error{Code: http.StatusNotFound}
	}
	m.version++
	m.value = req.Payload.Data
	return &secretmanagerpb.SecretVersion{
		Name: fmt.Sprintf("projects/mock/secrets/mock/versions/%d", m.version),
	}, nil
}

func (m *mockedGCPSecretManagerClient) DestroySecretVersion(_ context.Context, req *secretmanagerpb.DestroySecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	if !m.exists {
		return nil, &googleapi.Error{Code: http.StatusNotFound}
	}
	version := versionFromSecretID(req.Name)
	if version == 0 || version == m.version {
		return nil, &googleapi.Error{Code: http.StatusInternalServerError}
	}
	if version > m.version {
		return nil, &googleapi.Error{Code: http.StatusNotFound}
	}
	if m.deletedVersions[version] {
		return nil, &googleapi.Error{Code: http.StatusPreconditionFailed}
	}
	m.deletedVersions[version] = true
	return &secretmanagerpb.SecretVersion{
		Name: fmt.Sprintf("projects/mock/secrets/mock/versions/%d", version),
	}, nil
}

func TestGCPStoreString(t *testing.T) {
	store := &gcpStore{
		secretID: "projects/mock/secrets/mock",
	}
	want := "gcpStore(\"projects/mock/secrets/mock\")"
	if got := store.String(); got != want {
		t.Errorf("GCPStore.String = %q; want %q", got, want)
	}
}

func TestNewGCPStore(t *testing.T) {
	tstest.PanicOnLog()

	mc := newMockedGCPSecretManagerClient()
	secretID := "projects/mock/secrets/mock"

	s, err := newStore(secretID, mc)
	if err != nil {
		t.Fatalf("creating gcp store failed: %v", err)
	}
	storetest.TestStoreSemantics(t, s)

	// Build a brand new file store and check that both IDs written
	// above are still there.
	s2, err := newStore(secretID, mc)
	if err != nil {
		t.Fatalf("creating second gcp store failed: %v", err)
	}
	store2 := s.(*gcpStore)

	// This is specific to the test, with the non-mocked API, LoadState() should
	// have been already called and successful as no err is returned from NewAWSStore()
	s2.(*gcpStore).LoadState()

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
