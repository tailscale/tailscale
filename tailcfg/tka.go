// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailcfg

import (
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// TKAInitBeginRequest submits a genesis AUM to seed the creation of the
// tailnet's key authority.
type TKAInitBeginRequest struct {
	// Version is the client's capabilities.
	Version CapabilityVersion

	// NodeKey is the client's current node key.
	NodeKey key.NodePublic

	// GenesisAUM is the initial (genesis) AUM that the node generated
	// to bootstrap tailnet key authority state.
	GenesisAUM tkatype.MarshaledAUM
}

// TKASignInfo describes information about an existing node that needs
// to be signed into a node-key signature.
type TKASignInfo struct {
	// NodeID is the ID of the node which needs a signature. It must
	// correspond to NodePublic.
	NodeID NodeID
	// NodePublic is the node (Wireguard) public key which is being
	// signed.
	NodePublic key.NodePublic

	// RotationPubkey specifies the public key which may sign
	// a NodeKeySignature (NKS), which rotates the node key.
	//
	// This is necessary so the node can rotate its node-key without
	// talking to a node which holds a trusted network-lock key.
	// It does this by nesting the original NKS in a 'rotation' NKS,
	// which it then signs with the key corresponding to RotationPubkey.
	//
	// This field expects a raw ed25519 public key.
	RotationPubkey []byte
}

// TKAInitBeginResponse is the JSON response from a /tka/init/begin RPC.
// This structure describes node information which must be signed to
// complete initialization of the tailnets' key authority.
type TKAInitBeginResponse struct {
	// NeedSignatures specify information about the nodes in your tailnet
	// which need initial signatures to function once the tailnet key
	// authority is in use. The generated signatures should then be
	// submitted in a /tka/init/finish RPC.
	NeedSignatures []TKASignInfo
}

// TKAInitFinishRequest is the JSON request of a /tka/init/finish RPC.
// This RPC finalizes initialization of the tailnet key authority
// by submitting node-key signatures for all existing nodes.
type TKAInitFinishRequest struct {
	// Version is the client's capabilities.
	Version CapabilityVersion

	// NodeKey is the client's current node key.
	NodeKey key.NodePublic

	// Signatures are serialized tka.NodeKeySignatures for all nodes
	// in the tailnet.
	Signatures map[NodeID]tkatype.MarshaledSignature

	// SupportDisablement is a disablement secret for Tailscale support.
	// This is only generated if --gen-disablement-for-support is specified
	// in an invocation to 'tailscale lock init'.
	SupportDisablement []byte `json:",omitempty"`
}

// TKAInitFinishResponse is the JSON response from a /tka/init/finish RPC.
// This schema describes the successful enablement of the tailnet's
// key authority.
type TKAInitFinishResponse struct {
	// Nothing. (yet?)
}

// TKAInfo encodes the control plane's view of tailnet key authority (TKA)
// state. This information is transmitted as part of the MapResponse.
type TKAInfo struct {
	// Head describes the hash of the latest AUM applied to the authority.
	// Head is encoded as tka.AUMHash.MarshalText.
	//
	// If the Head state differs to that known locally, the node should perform
	// synchronization via a separate RPC.
	Head string `json:",omitempty"`

	// Disabled indicates the control plane believes TKA should be disabled,
	// and the node should reach out to fetch a disablement
	// secret. If the disablement secret verifies, then the node should then
	// disable TKA locally.
	// This field exists to disambiguate a nil TKAInfo in a delta mapresponse
	// from a nil TKAInfo indicating TKA should be disabled.
	Disabled bool `json:",omitempty"`
}

// TKABootstrapRequest is sent by a node to get information necessary for
// enabling or disabling the tailnet key authority.
type TKABootstrapRequest struct {
	// Version is the client's capabilities.
	Version CapabilityVersion

	// NodeKey is the client's current node key.
	NodeKey key.NodePublic

	// Head represents the node's head AUMHash (tka.Authority.Head), if
	// network lock is enabled.
	Head string
}

// TKABootstrapResponse encodes values necessary to enable or disable
// the tailnet key authority (TKA).
type TKABootstrapResponse struct {
	// GenesisAUM returns the initial AUM necessary to initialize TKA.
	GenesisAUM tkatype.MarshaledAUM `json:",omitempty"`

	// DisablementSecret encodes a secret necessary to disable TKA.
	DisablementSecret []byte `json:",omitempty"`
}

// TKASyncOfferRequest encodes a request to synchronize tailnet key authority
// state (TKA). Values of type tka.AUMHash are encoded as strings in their
// MarshalText form.
type TKASyncOfferRequest struct {
	// Version is the client's capabilities.
	Version CapabilityVersion

	// NodeKey is the client's current node key.
	NodeKey key.NodePublic

	// Head represents the node's head AUMHash (tka.Authority.Head). This
	// corresponds to tka.SyncOffer.Head.
	Head string
	// Ancestors represents a selection of ancestor AUMHash values ascending
	// from the current head. This corresponds to tka.SyncOffer.Ancestors.
	Ancestors []string
}

// TKASyncOfferResponse encodes a response in synchronizing a node's
// tailnet key authority state. Values of type tka.AUMHash are encoded as
// strings in their MarshalText form.
type TKASyncOfferResponse struct {
	// Head represents the control plane's head AUMHash (tka.Authority.Head).
	// This corresponds to tka.SyncOffer.Head.
	Head string
	// Ancestors represents a selection of ancestor AUMHash values ascending
	// from the control plane's head. This corresponds to
	// tka.SyncOffer.Ancestors.
	Ancestors []string
	// MissingAUMs encodes AUMs that the control plane believes the node
	// is missing.
	MissingAUMs []tkatype.MarshaledAUM
}

// TKASyncSendRequest encodes AUMs that a node believes the control plane
// is missing, and notifies control of its local TKA state (specifically
// the head hash).
type TKASyncSendRequest struct {
	// Version is the client's capabilities.
	Version CapabilityVersion

	// NodeKey is the client's current node key.
	NodeKey key.NodePublic

	// Head represents the node's head AUMHash (tka.Authority.Head) after
	// applying any AUMs from the sync-offer response.
	// It is encoded as tka.AUMHash.MarshalText.
	Head string

	// MissingAUMs encodes AUMs that the node believes the control plane
	// is missing.
	MissingAUMs []tkatype.MarshaledAUM

	// Interactive is true if additional error checking should be performed as
	// the request is on behalf of an interactive operation (e.g., an
	// administrator publishing new changes) as opposed to an automatic
	// synchronization that may be reporting lost data.
	Interactive bool
}

// TKASyncSendResponse encodes the control plane's response to a node
// submitting AUMs during AUM synchronization.
type TKASyncSendResponse struct {
	// Head represents the control plane's head AUMHash (tka.Authority.Head),
	// after applying the missing AUMs.
	Head string
}

// TKADisableRequest disables network-lock across the tailnet using the
// provided disablement secret.
//
// This is the request schema for a /tka/disable noise RPC.
type TKADisableRequest struct {
	// Version is the client's capabilities.
	Version CapabilityVersion

	// NodeKey is the client's current node key.
	NodeKey key.NodePublic

	// Head represents the node's head AUMHash (tka.Authority.Head).
	// It is encoded as tka.AUMHash.MarshalText.
	Head string

	// DisablementSecret encodes the secret necessary to disable TKA.
	DisablementSecret []byte
}

// TKADisableResponse is the JSON response from a /tka/disable RPC.
// This schema describes the successful disablement of the tailnet's
// key authority.
type TKADisableResponse struct {
	// Nothing. (yet?)
}

// TKASubmitSignatureRequest transmits a node-key signature to the control plane.
//
// This is the request schema for a /tka/sign noise RPC.
type TKASubmitSignatureRequest struct {
	// Version is the client's capabilities.
	Version CapabilityVersion

	// NodeKey is the client's current node key. The node-key which
	// is being signed is embedded in Signature.
	NodeKey key.NodePublic

	// Signature encodes the node-key signature being submitted.
	Signature tkatype.MarshaledSignature
}

// TKASubmitSignatureResponse is the JSON response from a /tka/sign RPC.
type TKASubmitSignatureResponse struct {
	// Nothing. (yet?)
}

// TKASignaturesUsingKeyRequest asks the control plane for
// all signatures which are signed by the provided keyID.
//
// This is the request schema for a /tka/affected-sigs RPC.
type TKASignaturesUsingKeyRequest struct {
	// Version is the client's capabilities.
	Version CapabilityVersion

	// NodeKey is the client's current node key.
	NodeKey key.NodePublic

	// KeyID is the key we are querying using.
	KeyID tkatype.KeyID
}

// TKASignaturesUsingKeyResponse is the JSON response to
// a /tka/affected-sigs RPC.
//
// It enumerates all signatures which are signed by the
// queried keyID.
type TKASignaturesUsingKeyResponse struct {
	Signatures []tkatype.MarshaledSignature
}
