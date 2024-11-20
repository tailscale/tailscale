// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubeclient

import (
	"context"
	"encoding/json"
	"net/http"
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
