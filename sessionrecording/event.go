// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sessionrecording

import (
	"net/url"

	"tailscale.com/tailcfg"
)

const (
	KubernetesAPIEventType = "kubernetes-api-request"
)

// Event represents the top-level structure of a tsrecorder event.
type Event struct {
	// Type specifies the kind of event being recorded (e.g., "kubernetes-api-request").
	Type string `json:"type"`

	// ID is a reference of the path that this event is stored at in tsrecorder
	ID string `json:"id"`

	// Timestamp is the time when the event was recorded represented as a unix timestamp.
	Timestamp int64 `json:"timestamp"`

	// UserAgent is the UerAgent specified in the request, which helps identify
	// the client software that initiated the request.
	UserAgent string `json:"userAgent"`

	// Request holds details of the HTTP request.
	Request Request `json:"request"`

	// Kubernetes contains Kubernetes-specific information about the request (if
	// the type is `kubernetes-api-request`)
	Kubernetes KubernetesRequestInfo `json:"kubernetes"`

	// Source provides details about the client that initiated the request.
	Source Source `json:"source"`

	// Destination provides details about the node receiving the request.
	Destination Destination `json:"destination"`
}

// copied from https://github.com/kubernetes/kubernetes/blob/11ade2f7dd264c2f52a4a1342458abbbaa3cb2b1/staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo.go#L44
// KubernetesRequestInfo contains Kubernetes specific information in the request (if the type is `kubernetes-api-request`)
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

	Namespace string
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

type Destination struct {
	// Node is the FQDN of the node receiving the connection.
	// It is also the MagicDNS name for the node.
	// It does not have a trailing dot.
	// e.g. "host.tail-scale.ts.net"
	Node string `json:"node"`

	// NodeID is the node ID of the node receiving the connection.
	NodeID tailcfg.StableNodeID `json:"nodeID"`
}

// Request holds information about a request.
type Request struct {
	Method          string     `json:"method"`
	Path            string     `json:"path"`
	Body            []byte     `json:"body"`
	QueryParameters url.Values `json:"queryParameters"`
}
