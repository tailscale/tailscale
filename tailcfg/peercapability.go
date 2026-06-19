package tailcfg

import (
	"encoding/json"
	"net/netip"

	"tailscale.com/types/views"
)

// CapGrant grants capabilities in a FilterRule.
type CapGrant struct {
	// Dsts are the destination IP ranges that this capability
	// grant matches.
	Dsts []netip.Prefix

	// Caps are the capabilities the source IP matched by
	// FilterRule.SrcIPs are granted to the destination IP,
	// matched by Dsts.
	// Deprecated: use CapMap instead.
	Caps []PeerCapability `json:",omitempty"`

	// CapMap is a map of capabilities to their values.
	// The key is the capability name, and the value is a list of
	// values for that capability.
	CapMap PeerCapMap `json:",omitempty"`
}

// PeerCapability represents a capability granted to a peer by a FilterRule when
// the peer communicates with the node that has this rule. Its meaning is
// application-defined.
//
// It must be a URL like "https://tailscale.com/cap/file-send".
type PeerCapability string

const (
	// PeerCapabilityFileSharingTarget grants the current node the ability to send
	// files to the peer which has this capability.
	PeerCapabilityFileSharingTarget PeerCapability = "https://tailscale.com/cap/file-sharing-target"
	// PeerCapabilityFileSharingSend grants the ability to receive files from a
	// node that's owned by a different user.
	PeerCapabilityFileSharingSend PeerCapability = "https://tailscale.com/cap/file-send"
	// PeerCapabilityDebugPeer grants the ability for a peer to read this node's
	// goroutines, metrics, magicsock internal state, etc.
	PeerCapabilityDebugPeer PeerCapability = "https://tailscale.com/cap/debug-peer"
	// PeerCapabilityWakeOnLAN grants the ability to send a Wake-On-LAN packet.
	PeerCapabilityWakeOnLAN PeerCapability = "https://tailscale.com/cap/wake-on-lan"
	// PeerCapabilityIngress grants the ability for a peer to send ingress traffic.
	PeerCapabilityIngress PeerCapability = "https://tailscale.com/cap/ingress"
	// PeerCapabilityWebUI grants the ability for a peer to edit features from the
	// device Web UI.
	PeerCapabilityWebUI PeerCapability = "tailscale.com/cap/webui"
	// PeerCapabilityTaildrive grants the ability for a peer to access Taildrive
	// shares.
	PeerCapabilityTaildrive PeerCapability = "tailscale.com/cap/drive"
	// PeerCapabilityTaildriveSharer indicates that a peer has the ability to
	// share folders with us.
	PeerCapabilityTaildriveSharer PeerCapability = "tailscale.com/cap/drive-sharer"

	// PeerCapabilityKubernetes grants a peer Kubernetes-specific
	// capabilities, such as the ability to impersonate specific Tailscale
	// user groups as Kubernetes user groups. This capability is read by
	// peers that are Tailscale Kubernetes operator instances.
	PeerCapabilityKubernetes PeerCapability = "tailscale.com/cap/kubernetes"

	// PeerCapabilityRelay grants the ability for a peer to allocate relay
	// endpoints.
	PeerCapabilityRelay PeerCapability = "tailscale.com/cap/relay"
	// PeerCapabilityRelayTarget grants the current node the ability to allocate
	// relay endpoints to the peer which has this capability.
	PeerCapabilityRelayTarget PeerCapability = "tailscale.com/cap/relay-target"

	// PeerCapabilityTsIDP grants a peer tsidp-specific
	// capabilities, such as the ability to add user groups to the OIDC
	// claim
	PeerCapabilityTsIDP PeerCapability = "tailscale.com/cap/tsidp"

	// PeerCapabilityConn25Prefix is the prefix for [PeerCapability] values
	// that grant a peer access to an app provided by a conn25 app connector.
	// Actual capabilities look like "tailscale.com/cap/conn25/app:example" for
	// an app named "example".
	// The [RawMessage] values are JSON-marshaled slices of [ProtoPortRange].
	// Typically, there is only a single value. If multiple values are present
	// then they should be treated the same as if appended into a single slice.
	// TODO(adrian): port filtering
	PeerCapabilityConn25Prefix PeerCapability = "sailorfrag.net/cap/conn25/"
)

// PeerCapMap is a map of capabilities to their optional values. It is valid for
// a capability to have no values (nil slice); such capabilities can be tested
// for by using the HasCapability method.
//
// The values are opaque to Tailscale, but are passed through from the ACLs to
// the application via the WhoIs API.
type PeerCapMap map[PeerCapability][]RawMessage

// UnmarshalCapJSON unmarshals each JSON value in cm[cap] as T.
// If cap does not exist in cm, it returns (nil, nil).
// It returns an error if the values cannot be unmarshaled into the provided type.
func UnmarshalCapJSON[T any](cm PeerCapMap, cap PeerCapability) ([]T, error) {
	return UnmarshalCapViewJSON[T](views.MapSliceOf(cm), cap)
}

// UnmarshalCapViewJSON unmarshals each JSON value in cm.Get(cap) as T.
// If cap does not exist in cm, it returns (nil, nil).
// It returns an error if the values cannot be unmarshaled into the provided type.
func UnmarshalCapViewJSON[T any](cm views.MapSlice[PeerCapability, RawMessage], cap PeerCapability) ([]T, error) {
	vals, ok := cm.GetOk(cap)
	if !ok {
		return nil, nil
	}
	out := make([]T, 0, vals.Len())
	for _, v := range vals.All() {
		var t T
		if err := json.Unmarshal([]byte(v), &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// HasCapability reports whether c has the capability cap. This is used to test
// for the existence of a capability, especially when the capability has no
// associated argument/data values.
func (c PeerCapMap) HasCapability(cap PeerCapability) bool {
	_, ok := c[cap]
	return ok
}
