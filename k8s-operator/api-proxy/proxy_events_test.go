// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package apiproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"testing"

	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/net/netx"
	"tailscale.com/sessionrecording"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

type fakeSender struct {
	sent  map[netip.AddrPort][]byte
	err   error
	calls int
}

func (s *fakeSender) Send(ap netip.AddrPort, event io.Reader, dial netx.DialFunc) error {
	s.calls++
	if s.err != nil {
		return s.err
	}
	if s.sent == nil {
		s.sent = make(map[netip.AddrPort][]byte)
	}
	data, _ := io.ReadAll(event)
	s.sent[ap] = data
	return nil
}

func (s *fakeSender) Reset() {
	s.sent = nil
	s.err = nil
	s.calls = 0
}

func TestRecordRequestAsEvent(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	sender := &fakeSender{}
	ap := &APIServerProxy{
		log:           zl.Sugar(),
		ts:            &tsnet.Server{},
		sendEventFunc: sender.Send,
		eventsEnabled: true,
	}

	defaultWho := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			StableID: "stable-id",
			Name:     "node.ts.net.",
		},
		UserProfile: &tailcfg.UserProfile{
			ID:        1,
			LoginName: "user@example.com",
		},
		CapMap: tailcfg.PeerCapMap{
			tailcfg.PeerCapabilityKubernetes: []tailcfg.RawMessage{
				tailcfg.RawMessage(`{"recorderAddrs":["127.0.0.1:1234"]}`),
				tailcfg.RawMessage(`{"enforceRecorder": true}`),
			},
		},
	}

	defaultSource := sessionrecording.Source{
		Node:       "node.ts.net",
		NodeID:     "stable-id",
		NodeUser:   "user@example.com",
		NodeUserID: 1,
	}

	tests := []struct {
		name         string
		req          func() *http.Request
		who          *apitype.WhoIsResponse
		setupSender  func()
		wantErr      bool
		wantEvent    *sessionrecording.Event
		wantNumCalls int
	}{
		{
			name: "request-with-dot-in-name",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/namespaces/default/pods/foo.bar", nil)
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/api/v1/namespaces/default/pods/foo.bar",
					Body:            nil,
					QueryParameters: url.Values{},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/namespaces/default/pods/foo.bar",
					Verb:              "get",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Namespace:         "default",
					Resource:          "pods",
					Name:              "foo.bar",
					Parts:             []string{"pods", "foo.bar"},
				},
				Source: defaultSource,
			},
		},
		{
			name: "request-with-dash-in-name",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/namespaces/default/pods/foo-bar", nil)
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/api/v1/namespaces/default/pods/foo-bar",
					Body:            nil,
					QueryParameters: url.Values{},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/namespaces/default/pods/foo-bar",
					Verb:              "get",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Namespace:         "default",
					Resource:          "pods",
					Name:              "foo-bar",
					Parts:             []string{"pods", "foo-bar"},
				},
				Source: defaultSource,
			},
		},
		{
			name: "request-with-query-parameter",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/pods?watch=true", nil)
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/api/v1/pods?watch=true",
					Body:            nil,
					QueryParameters: url.Values{"watch": []string{"true"}},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/pods",
					Verb:              "watch",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Resource:          "pods",
					Parts:             []string{"pods"},
				},
				Source: defaultSource,
			},
		},
		{
			name: "request-with-label-selector",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/pods?labelSelector=app%3Dfoo", nil)
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/api/v1/pods?labelSelector=app%3Dfoo",
					Body:            nil,
					QueryParameters: url.Values{"labelSelector": []string{"app=foo"}},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/pods",
					Verb:              "list",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Resource:          "pods",
					Parts:             []string{"pods"},
					LabelSelector:     "app=foo",
				},
				Source: defaultSource,
			},
		},
		{
			name: "request-with-field-selector",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/pods?fieldSelector=status.phase%3DRunning", nil)
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/api/v1/pods?fieldSelector=status.phase%3DRunning",
					Body:            nil,
					QueryParameters: url.Values{"fieldSelector": []string{"status.phase=Running"}},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/pods",
					Verb:              "list",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Resource:          "pods",
					Parts:             []string{"pods"},
					FieldSelector:     "status.phase=Running",
				},
				Source: defaultSource,
			},
		},
		{
			name: "request-for-non-existent-resource",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/foo", nil)
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/api/v1/foo",
					Body:            nil,
					QueryParameters: url.Values{},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/foo",
					Verb:              "list",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Resource:          "foo",
					Parts:             []string{"foo"},
				},
				Source: defaultSource,
			},
		},
		{
			name: "basic-request",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/pods", nil)
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/api/v1/pods",
					Body:            nil,
					QueryParameters: url.Values{},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/pods",
					Verb:              "list",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Resource:          "pods",
					Parts:             []string{"pods"},
				},
				Source: defaultSource,
			},
		},
		{
			name: "multiple-recorders",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/pods", nil)
			},
			who: &apitype.WhoIsResponse{
				Node:        defaultWho.Node,
				UserProfile: defaultWho.UserProfile,
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityKubernetes: []tailcfg.RawMessage{
						tailcfg.RawMessage(`{"recorderAddrs":["127.0.0.1:1234", "127.0.0.1:5678"]}`),
					},
				},
			},
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
		},
		{
			name: "request-with-body",
			req: func() *http.Request {
				req := httptest.NewRequest("POST", "/api/v1/pods", bytes.NewBufferString(`{"foo":"bar"}`))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "POST",
					Path:            "/api/v1/pods",
					Body:            json.RawMessage(`{"foo":"bar"}`),
					QueryParameters: url.Values{},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/pods",
					Verb:              "create",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Resource:          "pods",
					Parts:             []string{"pods"},
				},
				Source: defaultSource,
			},
		},
		{
			name: "tagged-node",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/pods", nil)
			},
			who: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{
					StableID: "stable-id",
					Name:     "node.ts.net.",
					Tags:     []string{"tag:foo"},
				},
				UserProfile: &tailcfg.UserProfile{},
				CapMap:      defaultWho.CapMap,
			},
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/api/v1/pods",
					Body:            nil,
					QueryParameters: url.Values{},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/pods",
					Verb:              "list",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Resource:          "pods",
					Parts:             []string{"pods"},
				},
				Source: sessionrecording.Source{
					Node:     "node.ts.net",
					NodeID:   "stable-id",
					NodeTags: []string{"tag:foo"},
				},
			},
		},
		{
			name: "no-recorders",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/pods", nil)
			},
			who: &apitype.WhoIsResponse{
				Node:        defaultWho.Node,
				UserProfile: defaultWho.UserProfile,
				CapMap:      tailcfg.PeerCapMap{},
			},
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 0,
		},
		{
			name: "error-sending",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/pods", nil)
			},
			who: defaultWho,
			setupSender: func() {
				sender.Reset()
				sender.err = errors.New("send error")
			},
			wantErr:      true,
			wantNumCalls: 1,
		},
		{
			name: "request-for-crd",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/apis/custom.example.com/v1/myresources", nil)
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/apis/custom.example.com/v1/myresources",
					Body:            nil,
					QueryParameters: url.Values{},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/apis/custom.example.com/v1/myresources",
					Verb:              "list",
					APIPrefix:         "apis",
					APIGroup:          "custom.example.com",
					APIVersion:        "v1",
					Resource:          "myresources",
					Parts:             []string{"myresources"},
				},
				Source: defaultSource,
			},
		},
		{
			name: "request-with-proxy-verb",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/namespaces/default/pods/foo/proxy", nil)
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/api/v1/namespaces/default/pods/foo/proxy",
					Body:            nil,
					QueryParameters: url.Values{},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/namespaces/default/pods/foo/proxy",
					Verb:              "get",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Namespace:         "default",
					Resource:          "pods",
					Subresource:       "proxy",
					Name:              "foo",
					Parts:             []string{"pods", "foo", "proxy"},
				},
				Source: defaultSource,
			},
		},
		{
			name: "request-with-complex-path",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/api/v1/namespaces/default/services/foo:8080/proxy-subpath/more/segments", nil)
			},
			who:          defaultWho,
			setupSender:  func() { sender.Reset() },
			wantNumCalls: 1,
			wantEvent: &sessionrecording.Event{
				Type: sessionrecording.KubernetesAPIEventType,
				Request: sessionrecording.Request{
					Method:          "GET",
					Path:            "/api/v1/namespaces/default/services/foo:8080/proxy-subpath/more/segments",
					Body:            nil,
					QueryParameters: url.Values{},
				},
				Kubernetes: sessionrecording.KubernetesRequestInfo{
					IsResourceRequest: true,
					Path:              "/api/v1/namespaces/default/services/foo:8080/proxy-subpath/more/segments",
					Verb:              "get",
					APIPrefix:         "api",
					APIVersion:        "v1",
					Namespace:         "default",
					Resource:          "services",
					Subresource:       "proxy-subpath",
					Name:              "foo:8080",
					Parts:             []string{"services", "foo:8080", "proxy-subpath", "more", "segments"},
				},
				Source: defaultSource,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupSender()

			req := tt.req()
			err := ap.recordRequestAsEvent(req, tt.who)

			if (err != nil) != tt.wantErr {
				t.Fatalf("recordRequestAsEvent() error = %v, wantErr %v", err, tt.wantErr)
			}

			if sender.calls != tt.wantNumCalls {
				t.Fatalf("expected %d calls to sender, got %d", tt.wantNumCalls, sender.calls)
			}

			if tt.wantEvent != nil {
				for _, sentData := range sender.sent {
					var got sessionrecording.Event
					if err := json.Unmarshal(sentData, &got); err != nil {
						t.Fatalf("failed to unmarshal sent event: %v", err)
					}

					got.Timestamp = 0
					tt.wantEvent.Timestamp = got.Timestamp

					got.UserAgent = ""
					tt.wantEvent.UserAgent = ""

					if !bytes.Equal(got.Request.Body, tt.wantEvent.Request.Body) {
						t.Errorf("sent event body does not match wanted event body.\nGot:  %s\nWant: %s", string(got.Request.Body), string(tt.wantEvent.Request.Body))
					}
					got.Request.Body = nil
					tt.wantEvent.Request.Body = nil

					if !reflect.DeepEqual(&got, tt.wantEvent) {
						t.Errorf("sent event does not match wanted event.\nGot:  %#v\nWant: %#v", &got, tt.wantEvent)
					}
				}
			}
		})
	}
}
