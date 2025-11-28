package cli

import (
	"bytes"
	"context"
	"os"
	"tailscale.com/ipn"
	"testing"
)

// Use a mock implementation of the LocalClient interface for testing
type mockLocalClient struct {
	mockAllProfiles    []ipn.LoginProfile
	mockCurrentProfile ipn.LoginProfile
	mockError          error
}

// Implement the ProfileStatus method for the mock
func (mlc *mockLocalClient) ProfileStatus(ctx context.Context) (current ipn.LoginProfile, all []ipn.LoginProfile, err error) {
	return mlc.mockCurrentProfile, mlc.mockAllProfiles, mlc.mockError
}

func TestListProfiles(t *testing.T) {
	tests := []struct {
		testName   string
		all        []ipn.LoginProfile
		curP       ipn.LoginProfile
		err        error
		wanted     string
		wantedJson string
	}{
		{
			testName:   "empty",
			all:        []ipn.LoginProfile{},
			curP:       ipn.LoginProfile{},
			err:        nil,
			wanted:     "ID  Tailnet  Account\n",
			wantedJson: "{\n  \"Current\": null,\n  \"Profiles\": []\n}\n",
		},
		{
			testName: "no active profile",
			all: []ipn.LoginProfile{
				{ID: "abcd", Name: "Profile1", NetworkProfile: ipn.NetworkProfile{DomainName: "example.com"}},
				{ID: "1234", Name: "Profile2", NetworkProfile: ipn.NetworkProfile{DomainName: "test.com"}},
			},
			curP: ipn.LoginProfile{},
			err:  nil,
			wanted: "ID    Tailnet      Account\n" +
				"abcd  example.com  Profile1\n" +
				"1234  test.com     Profile2\n",
			wantedJson: "{\n  \"Current\": null,\n  \"Profiles\": [\n    {\n      \"ID\": \"abcd\",\n      \"Name\": \"Profile1\",\n      \"NetworkProfile\": {\n        \"MagicDNSName\": \"\",\n        \"DomainName\": \"example.com\"\n      },\n      \"Key\": \"\",\n      \"UserProfile\": {\n        \"ID\": 0,\n        \"LoginName\": \"\",\n        \"DisplayName\": \"\",\n        \"ProfilePicURL\": \"\",\n        \"Roles\": []\n      },\n      \"NodeID\": \"\",\n      \"LocalUserID\": \"\",\n      \"ControlURL\": \"\"\n    },\n    {\n      \"ID\": \"1234\",\n      \"Name\": \"Profile2\",\n      \"NetworkProfile\": {\n        \"MagicDNSName\": \"\",\n        \"DomainName\": \"test.com\"\n      },\n      \"Key\": \"\",\n      \"UserProfile\": {\n        \"ID\": 0,\n        \"LoginName\": \"\",\n        \"DisplayName\": \"\",\n        \"ProfilePicURL\": \"\",\n        \"Roles\": []\n      },\n      \"NodeID\": \"\",\n      \"LocalUserID\": \"\",\n      \"ControlURL\": \"\"\n    }\n  ]\n}\n",
		},
		{
			testName: "one active profile",
			all: []ipn.LoginProfile{
				{ID: "abcd", Name: "Profile1", NetworkProfile: ipn.NetworkProfile{DomainName: "example.com"}},
				{ID: "1234", Name: "Profile2", NetworkProfile: ipn.NetworkProfile{DomainName: "test.com"}},
			},
			curP: ipn.LoginProfile{ID: "abcd", Name: "Profile1", NetworkProfile: ipn.NetworkProfile{DomainName: "example.com"}},
			err:  nil,
			wanted: "ID    Tailnet      Account\n" +
				"abcd  example.com  Profile1*\n" +
				"1234  test.com     Profile2\n",
			wantedJson: "{\n  \"Current\": {\n    \"ID\": \"abcd\",\n    \"Name\": \"Profile1\",\n    \"NetworkProfile\": {\n      \"MagicDNSName\": \"\",\n      \"DomainName\": \"example.com\"\n    },\n    \"Key\": \"\",\n    \"UserProfile\": {\n      \"ID\": 0,\n      \"LoginName\": \"\",\n      \"DisplayName\": \"\",\n      \"ProfilePicURL\": \"\",\n      \"Roles\": []\n    },\n    \"NodeID\": \"\",\n    \"LocalUserID\": \"\",\n    \"ControlURL\": \"\"\n  },\n  \"Profiles\": [\n    {\n      \"ID\": \"abcd\",\n      \"Name\": \"Profile1\",\n      \"NetworkProfile\": {\n        \"MagicDNSName\": \"\",\n        \"DomainName\": \"example.com\"\n      },\n      \"Key\": \"\",\n      \"UserProfile\": {\n        \"ID\": 0,\n        \"LoginName\": \"\",\n        \"DisplayName\": \"\",\n        \"ProfilePicURL\": \"\",\n        \"Roles\": []\n      },\n      \"NodeID\": \"\",\n      \"LocalUserID\": \"\",\n      \"ControlURL\": \"\"\n    },\n    {\n      \"ID\": \"1234\",\n      \"Name\": \"Profile2\",\n      \"NetworkProfile\": {\n        \"MagicDNSName\": \"\",\n        \"DomainName\": \"test.com\"\n      },\n      \"Key\": \"\",\n      \"UserProfile\": {\n        \"ID\": 0,\n        \"LoginName\": \"\",\n        \"DisplayName\": \"\",\n        \"ProfilePicURL\": \"\",\n        \"Roles\": []\n      },\n      \"NodeID\": \"\",\n      \"LocalUserID\": \"\",\n      \"ControlURL\": \"\"\n    }\n  ]\n}\n",
		},
	}

	oldLocalClientProfileStatus := LocalClientProfileStatus
	defer func() { LocalClientProfileStatus = oldLocalClientProfileStatus }()
	defer func() { Stdout = os.Stdout }()

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			// mock the localClient.ProfileStatus
			mockClient := &mockLocalClient{
				mockAllProfiles:    tt.all,
				mockCurrentProfile: tt.curP,
				mockError:          tt.err,
			}
			LocalClientProfileStatus = mockClient.ProfileStatus

			// capture stdout to compare it with expected test case result
			var buf bytes.Buffer
			Stdout = &buf

			// Simulate calling the "listProfiles" function with test data
			if err := listProfiles(context.Background()); err != nil {
				t.Errorf("listProfiles() error = %v", err)
			}

			got := buf.String()

			// Validate the output against the expected result
			if got != tt.wanted {
				t.Errorf("listProfiles() = %q, wanted %q", got, tt.wanted)
			}
		})
	}

	// Enable Json output
	switchArgs.json = true
	for _, tt := range tests {
		t.Run(tt.testName+" as Json", func(t *testing.T) {
			// mock the localClient.ProfileStatus
			mockClient := &mockLocalClient{
				mockAllProfiles:    tt.all,
				mockCurrentProfile: tt.curP,
				mockError:          tt.err,
			}
			LocalClientProfileStatus = mockClient.ProfileStatus

			// capture stdout to compare it with expected test case result
			var buf bytes.Buffer
			Stdout = &buf

			// Simulate calling the "listProfiles" function with test data
			if err := listProfiles(context.Background()); err != nil {
				t.Errorf("listProfiles() error = %v", err)
			}

			got := buf.String()

			// Validate the output against the expected result
			if got != tt.wantedJson {
				t.Errorf("listProfiles() = %q, wanted %q", got, tt.wantedJson)
			}
		})
	}
}
