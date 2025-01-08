package tailscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestClient_ACL(t *testing.T) {
	I_Acknowledge_This_API_Is_Unstable = true
	defer func() {
		I_Acknowledge_This_API_Is_Unstable = false
	}()

	t.Run("happy path", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Path, "/api/v2/tailnet/-/acl") {
				t.Errorf("unexpected URL: %v", r.URL.Path)
			}

			if "application/json" != r.Header.Get("Accept") {
				t.Errorf("unexpected Accept header: %v", r.Header.Get("Accept"))
			}

			if "tailscale-client-oss" != r.Header.Get("User-Agent") {
				t.Errorf("unexpected User-Agent header: %v", r.Header.Get("User-Agent"))
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
  "tests": [
    {
      "src": "192.168.1.1",
      "user": "user@example.com",
      "proto": "tcp",
      "accept": ["10.0.0.1:80", "10.0.0.2:443"],
      "deny": ["10.0.0.3:22"],
      "allow": ["10.0.0.1:80"]
    }
  ],
  "acls": [
    {
      "action": "accept",
      "proto": "tcp",
      "users": ["user1", "user2"],
      "ports": ["22", "80"],
      "src": ["192.168.1.1", "192.168.1.2"],
      "dst": ["10.0.0.1", "10.0.0.2"]
    }
  ],
  "groups": {
    "admins": ["admin1@example.com", "admin2@example.com"],
    "users": ["user1@example.com", "user2@example.com"]
  },
  "tagowners": {
    "tag:webserver": ["owner1@example.com", "owner2@example.com"]
  },
  "hosts": {
    "host1": "192.168.1.10",
    "host2": "192.168.1.11"
  },
  "nodeAttrs": [
    {
      "target": ["tag:webserver", "group:admins"],
      "attr": ["can-deploy", "read-only"]
    }
  ],
  "e_tag": "abc123xyz"
}`))
		}))
		defer ts.Close()

		tsClient := NewClient("-", nil)
		tsClient.BaseURL = ts.URL

		got, err := tsClient.ACL(context.TODO())
		if err != nil {
			t.Errorf("ACL() failed: %v", err)
		}

		expectedACL := &ACL{
			ACL: ACLDetails{
				Tests: []ACLTest{
					{
						Src:    "192.168.1.1",
						User:   "user@example.com",
						Proto:  "tcp",
						Accept: []string{"10.0.0.1:80", "10.0.0.2:443"},
						Deny:   []string{"10.0.0.3:22"},
						Allow:  []string{"10.0.0.1:80"},
					},
				},
				ACLs: []ACLRow{
					{
						Action: "accept",
						Proto:  "tcp",
						Users:  []string{"user1", "user2"},
						Ports:  []string{"22", "80"},
						Src:    []string{"192.168.1.1", "192.168.1.2"},
						Dst:    []string{"10.0.0.1", "10.0.0.2"},
					},
				},
				Groups: map[string][]string{
					"admins": {"admin1@example.com", "admin2@example.com"},
					"users":  {"user1@example.com", "user2@example.com"},
				},
				TagOwners: map[string][]string{
					"tag:webserver": {"owner1@example.com", "owner2@example.com"},
				},
				Hosts: map[string]string{
					"host1": "192.168.1.10",
					"host2": "192.168.1.11",
				},
				NodeAttrs: []NodeAttrGrant{
					{
						Target: []string{"tag:webserver", "group:admins"},
						Attr:   []string{"can-deploy", "read-only"},
					},
				},
			},
			ETag: "abc123xyz",
		}
		if reflect.DeepEqual(got, expectedACL) {
			t.Errorf("ACL() returned a different ACL: got %v, want %v", got, expectedACL)
		}
	})

	t.Run("server error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{
  "Status": 500,
  "Message": "Internal Server Error"
}`))
		}))
		defer ts.Close()

		tsClient := NewClient("-", nil)
		tsClient.BaseURL = ts.URL

		got, err := tsClient.ACL(context.TODO())
		if err == nil {
			t.Errorf("ACL() returned no error but expected one")
		}

		if got != nil {
			t.Errorf("ACL() returned a non-nil ACL: got %v, want nil", got)
		}
	})

	t.Run("server returns invalid JSON", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`invalid json`))
		}))
		defer ts.Close()

		tsClient := NewClient("-", nil)
		tsClient.BaseURL = ts.URL

		got, err := tsClient.ACL(context.TODO())
		if err == nil {
			t.Errorf("ACL() returned no error but expected one")
		}

		if got != nil {
			t.Errorf("ACL() returned a non-nil ACL: got %v, want nil", got)
		}
	})
}
