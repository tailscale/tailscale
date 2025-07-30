// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubeclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/tstest"
)

func Test_client_Event(t *testing.T) {
	cl := &tstest.Clock{}
	tests := []struct {
		name    string
		typ     string
		reason  string
		msg     string
		argSets []args
		wantErr bool
	}{
		{
			name:   "new_event_gets_created",
			typ:    "Normal",
			reason: "TestReason",
			msg:    "TestMessage",
			argSets: []args{
				{ // request to GET event returns not found
					wantsMethod: "GET",
					wantsURL:    "test-apiserver/api/v1/namespaces/test-ns/events/test-pod.test-uid.testreason",
					setErr:      &kubeapi.Status{Code: 404},
				},
				{ // sends POST request to create event
					wantsMethod: "POST",
					wantsURL:    "test-apiserver/api/v1/namespaces/test-ns/events",
					wantsIn: &kubeapi.Event{
						ObjectMeta: kubeapi.ObjectMeta{
							Name:      "test-pod.test-uid.testreason",
							Namespace: "test-ns",
						},
						Type:    "Normal",
						Reason:  "TestReason",
						Message: "TestMessage",
						Source: kubeapi.EventSource{
							Component: "test-client",
						},
						InvolvedObject: kubeapi.ObjectReference{
							Name:       "test-pod",
							UID:        "test-uid",
							Namespace:  "test-ns",
							APIVersion: "v1",
							Kind:       "Pod",
						},
						FirstTimestamp: cl.Now(),
						LastTimestamp:  cl.Now(),
						Count:          1,
					},
				},
			},
		},
		{
			name:   "existing_event_gets_patched",
			typ:    "Warning",
			reason: "TestReason",
			msg:    "TestMsg",
			argSets: []args{
				{ // request to GET event does not error - this is enough to assume that event exists
					wantsMethod: "GET",
					wantsURL:    "test-apiserver/api/v1/namespaces/test-ns/events/test-pod.test-uid.testreason",
					setOut:      []byte(`{"count":2}`),
				},
				{ // sends PATCH request to update the event
					wantsMethod: "PATCH",
					wantsURL:    "test-apiserver/api/v1/namespaces/test-ns/events/test-pod.test-uid.testreason",
					wantsIn: []JSONPatch{
						{Op: "replace", Path: "/count", Value: int32(3)},
						{Op: "replace", Path: "/lastTimestamp", Value: cl.Now()},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &client{
				cl:             cl,
				name:           "test-client",
				podName:        "test-pod",
				podUID:         "test-uid",
				url:            "test-apiserver",
				ns:             "test-ns",
				kubeAPIRequest: fakeKubeAPIRequest(t, tt.argSets),
				hasEventsPerms: true,
			}
			if err := c.Event(context.Background(), tt.typ, tt.reason, tt.msg); (err != nil) != tt.wantErr {
				t.Errorf("client.Event() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestReturnsKubeStatusError ensures HTTP error codes from the Kubernetes API
// server can always be extracted by casting the error to the *kubeapi.Status
// type, as lots of calling code relies on this cast succeeding. Note that
// transport errors are not expected or required to be of type *kubeapi.Status.
func TestReturnsKubeStatusError(t *testing.T) {
	cl := clientForKubeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(kubeapi.Status{Code: http.StatusForbidden, Message: "test error"})
	}))

	_, err := cl.GetSecret(t.Context(), "test-secret")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if st, ok := err.(*kubeapi.Status); !ok || st.Code != http.StatusForbidden {
		t.Fatalf("expected kubeapi.Status with code %d, got %T: %v", http.StatusForbidden, err, err)
	}
}

// clientForKubeHandler creates a client using the externally accessible package
// API to ensure it's testing behaviour as close to prod as possible. The passed
// in handler mocks the Kubernetes API server's responses to any HTTP requests
// made by the client.
func clientForKubeHandler(t *testing.T, handler http.Handler) Client {
	t.Helper()
	tmpDir := t.TempDir()
	rootPathForTests = tmpDir
	saDir := filepath.Join(tmpDir, "var", "run", "secrets", "kubernetes.io", "serviceaccount")
	_ = os.MkdirAll(saDir, 0755)
	_ = os.WriteFile(filepath.Join(saDir, "token"), []byte("test-token"), 0600)
	_ = os.WriteFile(filepath.Join(saDir, "namespace"), []byte("test-namespace"), 0600)
	_ = os.WriteFile(filepath.Join(saDir, "ca.crt"), []byte(ca), 0644)
	cl, err := New("test-client")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cl.SetURL(srv.URL)
	return cl
}

// args is a set of values for testing a single call to client.kubeAPIRequest.
type args struct {
	// wantsMethod is the expected value of 'method' arg.
	wantsMethod string
	// wantsURL is the expected value of 'url' arg.
	wantsURL string
	// wantsIn is the expected value of 'in' arg.
	wantsIn any
	// setOut can be set to a byte slice representing valid JSON. If set 'out' arg will get set to the unmarshalled
	// JSON object.
	setOut []byte
	// setErr is the error that kubeAPIRequest will return.
	setErr error
}

// fakeKubeAPIRequest can be used to test that a series of calls to client.kubeAPIRequest gets called with expected
// values and to set these calls to return preconfigured values. 'argSets' should be set to a slice of expected
// arguments and should-be return values of a series of kubeAPIRequest calls.
func fakeKubeAPIRequest(t *testing.T, argSets []args) kubeAPIRequestFunc {
	count := 0
	f := func(ctx context.Context, gotMethod, gotUrl string, gotIn, gotOut any, opts ...func(*http.Request)) error {
		t.Helper()
		if count >= len(argSets) {
			t.Fatalf("unexpected call to client.kubeAPIRequest, expected %d calls, but got a %dth call", len(argSets), count+1)
		}
		a := argSets[count]
		if gotMethod != a.wantsMethod {
			t.Errorf("[%d] got method %q, wants method %q", count, gotMethod, a.wantsMethod)
		}
		if gotUrl != a.wantsURL {
			t.Errorf("[%d] got URL %q, wants URL %q", count, gotUrl, a.wantsURL)
		}
		if d := cmp.Diff(gotIn, a.wantsIn); d != "" {
			t.Errorf("[%d] unexpected payload (-want + got):\n%s", count, d)
		}
		if len(a.setOut) != 0 {
			if err := json.Unmarshal(a.setOut, gotOut); err != nil {
				t.Fatalf("[%d] error unmarshalling output: %v", count, err)
			}
		}
		count++
		return a.setErr
	}
	return f
}

const ca = `-----BEGIN CERTIFICATE-----
MIIFEDCCA3igAwIBAgIRANf5NdPojIfj70wMfJVYUg8wDQYJKoZIhvcNAQELBQAw
gZ8xHjAcBgNVBAoTFW1rY2VydCBkZXZlbG9wbWVudCBDQTE6MDgGA1UECwwxZnJv
bWJlcmdlckBzdGFyZHVzdC5sb2NhbCAoTWljaGFlbCBKLiBGcm9tYmVyZ2VyKTFB
MD8GA1UEAww4bWtjZXJ0IGZyb21iZXJnZXJAc3RhcmR1c3QubG9jYWwgKE1pY2hh
ZWwgSi4gRnJvbWJlcmdlcikwHhcNMjMwMjA3MjAzNDE4WhcNMzMwMjA3MjAzNDE4
WjCBnzEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMTowOAYDVQQLDDFm
cm9tYmVyZ2VyQHN0YXJkdXN0LmxvY2FsIChNaWNoYWVsIEouIEZyb21iZXJnZXIp
MUEwPwYDVQQDDDhta2NlcnQgZnJvbWJlcmdlckBzdGFyZHVzdC5sb2NhbCAoTWlj
aGFlbCBKLiBGcm9tYmVyZ2VyKTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoC
ggGBAL5uXNnrZ6dgjcvK0Hc7ZNUIRYEWst9qbO0P9H7le08pJ6d9T2BUWruZtVjk
Q12msv5/bVWHhVk8dZclI9FLXuMsIrocH8bsoP4wruPMyRyp6EedSKODN51fFSRv
/jHbS5vzUVAWTYy9qYmd6qL0uhsHCZCCT6gfigamHPUFKM3sHDn5ZHWvySMwcyGl
AicmPAIkBWqiCZAkB5+WM7+oyRLjmrIalfWIZYxW/rojGLwTfneHv6J5WjVQnpJB
ayWCzCzaiXukK9MeBWeTOe8UfVN0Engd74/rjLWvjbfC+uZSr6RVkZvs2jANLwPF
zgzBPHgRPfAhszU1NNAMjnNQ47+OMOTKRt7e6jYzhO5fyO1qVAAvGBqcfpj+JfDk
cccaUMhUvdiGrhGf1V1tN/PislxvALirzcFipjD01isBKwn0fxRugzvJNrjEo8RA
RvbcdeKcwex7M0o/Cd0+G2B13gZNOFvR33PmG7iTpp7IUrUKfQg28I83Sp8tMY3s
ljJSawIDAQABo0UwQzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIB
ADAdBgNVHQ4EFgQU18qto0Fa56kCi/HwfQuC9ECX7cAwDQYJKoZIhvcNAQELBQAD
ggGBAAzs96LwZVOsRSlBdQqMo8oMAvs7HgnYbXt8SqaACLX3+kJ3cV/vrCE3iJrW
ma4CiQbxS/HqsiZjota5m4lYeEevRnUDpXhp+7ugZTiz33Flm1RU99c9UYfQ+919
ANPAKeqNpoPco/HF5Bz0ocepjcfKQrVZZNTj6noLs8o12FHBLO5976AcF9mqlNfh
8/F0gDJXq6+x7VT5y8u0rY004XKPRe3CklRt8kpeMiP6mhRyyUehOaHeIbNx8ubi
Pi44ByN/ueAnuRhF9zYtyZVZZOaSLysJge01tuPXF8rBXGruoJIv35xTTBa9BzaP
YDOGbGn1ZnajdNagHqCba8vjTLDSpqMvgRj3TFrGHdETA2LDQat38uVxX8gxm68K
va5Tyv7n+6BQ5YTpJjTPnmSJKaXZrrhdLPvG0OU2TxeEsvbcm5LFQofirOOw86Se
vzF2cQ94mmHRZiEk0Av3NO0jF93ELDrBCuiccVyEKq6TknuvPQlutCXKDOYSEb8I
MHctBg==
-----END CERTIFICATE-----`
