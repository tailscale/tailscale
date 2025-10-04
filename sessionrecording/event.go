// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sessionrecording

import (
	"encoding/json"
	"time"

	"tailscale.com/tailcfg"
)

const (
	KubernetesAPIEventType = "Kubernetes API Request"
)

// Event represents the top-level structure of a tsrecorder event.
type Event struct {
	Type       string                `json:"type"`
	ID         string                `json:"id"`
	Timestamp  time.Time             `json:"timestamp"`
	UserAgent  string                `json:"userAgent"`
	Request    Request               `json:"request"`
	Kubernetes KubernetesRequestInfo `json:"kubernetes"`
	Source     Source                `json:"source"`
	LocalUser  string                `json:"localUser"`
}

// copied from https://github.com/kubernetes/kubernetes/blob/11ade2f7dd264c2f52a4a1342458abbbaa3cb2b1/staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo.go#L44
// KubernetesRequestInfo holds information parsed from the http.Request
type KubernetesRequestInfo struct {
	// IsResourceRequest indicates whether or not the request is for an API resource or subresource
	IsResourceRequest bool
	// Path is the URL path of the request
	Path string
	// Verb is the kube verb associated with the request for API requests, not the http verb.  This includes things like list and watch.
	// for non-resource requests, this is the lowercase http verb
	Verb string

	APIPrefix  string
	APIGroup   string
	APIVersion string
	Namespace  string
	// Resource is the name of the resource being requested.  This is not the kind.  For example: pods
	Resource string
	// Subresource is the name of the subresource being requested.  This is a different resource, scoped to the parent resource, but it may have a different kind.
	// For instance, /pods has the resource "pods" and the kind "Pod", while /pods/foo/status has the resource "pods", the sub resource "status", and the kind "Pod"
	// (because status operates on pods). The binding resource for a pod though may be /pods/foo/binding, which has resource "pods", subresource "binding", and kind "Binding".
	Subresource string
	// Name is empty for some verbs, but if the request directly indicates a name (not in body content) then this field is filled in.
	Name string
	// Parts are the path parts for the request, always starting with /{resource}/{name}
	Parts []string

	// FieldSelector contains the unparsed field selector from a request.  It is only present if the apiserver
	// honors field selectors for the verb this request is associated with.
	FieldSelector string
	// LabelSelector contains the unparsed field selector from a request.  It is only present if the apiserver
	// honors field selectors for the verb this request is associated with.
	LabelSelector string
}

type Source struct {
	// Node is the FQDN of the node originating the connection.
	// It is also the MagicDNS name for the node.
	// It does not have a trailing dot.
	// e.g. "host.tail-scale.ts.net"
	Node string `json:"node"`

	// NodeID is the node ID of the node originating the connection.
	NodeID tailcfg.StableNodeID `json:"nodeID"`

	// Tailscale-specific fields:
	// NodeTags is the list of tags on the node originating the connection (if any).
	NodeTags []string `json:"nodeTags,omitempty"`

	// NodeUserID is the user ID of the node originating the connection (if not tagged).
	NodeUserID tailcfg.UserID `json:"nodeUserID,omitempty"` // if not tagged

	// NodeUser is the LoginName of the node originating the connection (if not tagged).
	NodeUser string `json:"nodeUser,omitempty"`
}

// Request holds information about a request.
type Request struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"` // Using json.RawMessage to handle arbitrary JSON content
}

// Kubernetes contains Kubernetes-specific event details.
type KubernetesEvent struct {
	IsResourceRequest bool   `json:"isResourceRequest"`
	Verb              string `json:"verb"`
	APIGroup          string `json:"apiGroup"`
	APIVersion        string `json:"apiVersion"`
	Resource          string `json:"resource"`
	Subresource       string `json:"subresource"`
	Namespace         string `json:"namespace"`
	Name              string `json:"name"`
}

// User represents the user who initiated the event.
type User struct {
	Email string `json:"email"`
}
