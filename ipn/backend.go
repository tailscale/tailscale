// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"tailscale.com/drive"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/structs"
	"tailscale.com/types/views"
	"tailscale.com/util/syspolicy/policyclient"
)

type State int

const (
	NoState          State = 0
	InUseOtherUser   State = 1
	NeedsLogin       State = 2
	NeedsMachineAuth State = 3
	Stopped          State = 4
	Starting         State = 5
	Running          State = 6
)

// GoogleIDToken Type is the tailcfg.Oauth2Token.TokenType for the Google
// ID tokens used by the Android client.
const GoogleIDTokenType = "ts_android_google_login"

var stateStrings = [...]string{
	"NoState",
	"InUseOtherUser",
	"NeedsLogin",
	"NeedsMachineAuth",
	"Stopped",
	"Starting",
	"Running",
}

func (s State) String() string {
	return stateStrings[s]
}

// StateFromString parses s as a State string value.
func StateFromString(s string) (_ State, ok bool) {
	i := slices.Index(stateStrings[:], s)
	if i == -1 {
		return NoState, false
	}
	return State(i), true
}

// EngineStatus contains WireGuard engine stats.
type EngineStatus struct {
	RBytes, WBytes int64
	NumLive        int
	LiveDERPs      int // number of active DERP connections
	LivePeers      map[key.NodePublic]ipnstate.PeerStatusLite
}

// NotifyWatchOpt is a bitmask of options about what type of Notify messages
// to subscribe to.
type NotifyWatchOpt uint64

// NotifyWatchOpt values.
//
// These aren't declared using Go's iota because they're not purely internal to
// the process and iota should not be used for values that are serialized to
// disk or network. In this case, these values come over the network via the
// LocalAPI, a mostly stable API.
const (
	// NotifyWatchEngineUpdates, if set, causes Engine updates to be sent to the
	// client either regularly or when they change, without having to ask for
	// each one via Engine.RequestStatus.
	NotifyWatchEngineUpdates NotifyWatchOpt = 1 << 0

	NotifyInitialState  NotifyWatchOpt = 1 << 1 // if set, the first Notify message (sent immediately) will contain the current State + BrowseToURL + SessionID
	NotifyInitialPrefs  NotifyWatchOpt = 1 << 2 // if set, the first Notify message (sent immediately) will contain the current Prefs
	NotifyInitialNetMap NotifyWatchOpt = 1 << 3 // if set, the first Notify message (sent immediately) will contain the current NetMap

	NotifyNoPrivateKeys        NotifyWatchOpt = 1 << 4 // (no-op) it used to redact private keys; now they always are and this does nothing
	NotifyInitialDriveShares   NotifyWatchOpt = 1 << 5 // if set, the first Notify message (sent immediately) will contain the current Taildrive Shares
	NotifyInitialOutgoingFiles NotifyWatchOpt = 1 << 6 // if set, the first Notify message (sent immediately) will contain the current Taildrop OutgoingFiles

	NotifyInitialHealthState NotifyWatchOpt = 1 << 7 // if set, the first Notify message (sent immediately) will contain the current health.State of the client

	NotifyRateLimit NotifyWatchOpt = 1 << 8 // if set, rate limit spammy netmap updates to every few seconds

	NotifyHealthActions NotifyWatchOpt = 1 << 9 // if set, include PrimaryActions in health.State. Otherwise append the action URL to the text

	NotifyInitialSuggestedExitNode NotifyWatchOpt = 1 << 10 // if set, the first Notify message (sent immediately) will contain the current SuggestedExitNode if available

	NotifyInitialClientVersion NotifyWatchOpt = 1 << 11 // if set, the first Notify message (sent immediately) will contain the current ClientVersion if available and if update checks are enabled

	// NotifyPeerChanges, if set, opts the watcher into peer-set delta
	// notifications: [Notify.PeersChanged] (peer added or full-Node
	// replaced) and [Notify.PeersRemoved] (peer removed by NodeID).
	//
	// Without this bit, peer adds/removes/replacements are not delivered
	// over the bus at all (consumers fall back to fetching the netmap on
	// demand or, on legacy-emit platforms, to watching [Notify.NetMap]).
	//
	// Watchers that want narrower per-field updates as well (Online,
	// LastSeen, DERPHome, Endpoints) should additionally set
	// [NotifyPeerPatches]. Without [NotifyPeerPatches], any per-field
	// patch tailscaled would have emitted as a [tailcfg.PeerChange] is
	// promoted into a full-Node entry in [Notify.PeersChanged] for this
	// watcher, so a watcher that opts only into [NotifyPeerChanges] still
	// observes every per-peer mutation; it just receives them as full
	// Nodes rather than narrow patches. The cost is bus bandwidth.
	//
	// On platforms where the legacy [Notify.NetMap] is still emitted
	// (Windows, macOS, iOS, Android), it is permitted to combine this
	// with [NotifyInitialNetMap] for backwards compatibility. New code
	// should pair this with [NotifyInitialStatus] instead.
	NotifyPeerChanges NotifyWatchOpt = 1 << 12

	// NotifyNoNetMap, if set, suppresses the legacy [Notify.NetMap] field on
	// runtime (non-initial) Notify messages delivered to this watcher. It
	// only matters on platforms where tailscaled still emits NetMap on the
	// bus by default — Windows, macOS, and iOS — and is intended for GUI
	// clients on those platforms that have migrated to read peers via
	// [Notify.PeersChanged] / [LocalClient.NetMap]. The initial-state NetMap
	// (sent when [NotifyInitialNetMap] is set) is unaffected.
	NotifyNoNetMap NotifyWatchOpt = 1 << 13

	// NotifyInitialStatus, if set, causes the first Notify message (sent
	// immediately) to contain the current [ipnstate.Status] in
	// [Notify.InitialStatus]. Together with [Notify.SelfChange] and
	// [Notify.PeersChanged] on subsequent messages, it lets a watcher
	// stitch together a continuous view of the local node's state without
	// fetching the netmap directly. Prefer this over [LocalClient.NetMap]
	// for new code that wants a stable, client-facing snapshot type.
	NotifyInitialStatus NotifyWatchOpt = 1 << 14

	// NotifyPeerPatches, if set, opts the watcher into narrow per-field
	// peer patches via [Notify.PeerChangedPatch]. It implies
	// [NotifyPeerChanges]: a watcher with [NotifyPeerPatches] also
	// receives [Notify.PeersChanged] and [Notify.PeersRemoved].
	//
	// This is the lower-bandwidth mode: changes to fields that fit in a
	// [tailcfg.PeerChange] (currently Online, LastSeen, DERPHome,
	// Endpoints) ride as patches; only changes that don't fit ride as
	// full Nodes in [Notify.PeersChanged].
	//
	// Without this bit but with [NotifyPeerChanges], the producer
	// promotes any patch into a full-Node entry in [Notify.PeersChanged]
	// for this session, at the cost of bandwidth.
	NotifyPeerPatches NotifyWatchOpt = 1 << 15

	// NotifyInProcessNoDisconnect, if set, marks this watcher as an
	// in-process subscriber that must not be disconnected for falling behind
	// on its notification queue. Instead, if its queue fills, Notify
	// production blocks until the watcher catches up.
	//
	// Callers using this bit must receive and process notifications promptly.
	// Their callbacks must not call back into LocalBackend or wait on work that
	// might call back into LocalBackend, because the producer might be holding
	// LocalBackend's mutex while waiting for the watcher to catch up.
	//
	// This bit is only valid for in-process callers of
	// LocalBackend.WatchNotificationsAs. LocalAPI WatchIPNBus clients must
	// not request it.
	NotifyInProcessNoDisconnect NotifyWatchOpt = 1 << 16

	// NotifySysPolicyChanges, if set, causes the first Notify message, which is sent
	// immediately, to contain the current effective [setting.Snapshot] in
	// [Notify.Policy]. [Notify.Policy] is included in subsequent messages whenever
	// the effective policy changes.
	//
	// The snapshot is scoped to the connected user's identity (on Windows,
	// derived from the named-pipe token's SID).
	//
	// The [setting.Snapshot] that is delivered is a full snapshot on every
	// change.
	NotifySysPolicyChanges NotifyWatchOpt = 1 << 17

	// NotifyPeerWireGuardState, if set, opts the watcher into
	// WireGuard session state notifications via [Notify.PeerState].
	// The first Notify sent to the watcher includes a dump of current
	// non-zero peer states, and subsequent Notifies include per-peer
	// state changes.
	NotifyPeerWireGuardState NotifyWatchOpt = 1 << 18
)

// String implements the [fmt.Stringer] interface.
// Returns the string representation of all the bits joined by the bitwise-or "|" operator.
func (o NotifyWatchOpt) String() string {
	if o == NotifyWatchOpt(0) {
		return fmt.Sprintf("%T(%#x)", o, uint64(o))
	}

	pkg, _, found := strings.Cut(fmt.Sprintf("%T", o), ".")

	var bits []string
	var mask NotifyWatchOpt
	try := func(bit NotifyWatchOpt, s string) {
		if o&bit == 0 {
			return
		}
		if found {
			bits = append(bits, pkg+"."+s)
		} else {
			bits = append(bits, s)
		}
		mask |= bit
	}
	try(NotifyWatchEngineUpdates, "NotifyWatchEngineUpdates")
	try(NotifyInitialState, "NotifyInitialState")
	try(NotifyInitialPrefs, "NotifyInitialPrefs")
	try(NotifyInitialNetMap, "NotifyInitialNetMap")
	try(NotifyNoPrivateKeys, "NotifyNoPrivateKeys")
	try(NotifyInitialDriveShares, "NotifyInitialDriveShares")
	try(NotifyInitialOutgoingFiles, "NotifyInitialOutgoingFiles")
	try(NotifyInitialHealthState, "NotifyInitialHealthState")
	try(NotifyRateLimit, "NotifyRateLimit")
	try(NotifyHealthActions, "NotifyHealthActions")
	try(NotifyInitialSuggestedExitNode, "NotifyInitialSuggestedExitNode")
	try(NotifyInitialClientVersion, "NotifyInitialClientVersion")
	try(NotifyPeerChanges, "NotifyPeerChanges")
	try(NotifyNoNetMap, "NotifyNoNetMap")
	try(NotifyInitialStatus, "NotifyInitialStatus")
	try(NotifyPeerPatches, "NotifyPeerPatches")
	try(NotifyInProcessNoDisconnect, "NotifyInProcessNoDisconnect")
	try(NotifySysPolicyChanges, "NotifySysPolicyChanges")
	try(NotifyPeerWireGuardState, "NotifyPeerWireGuardState")

	if mask != o {
		bits = append(bits, fmt.Sprintf("%T(%#x)", o, uint64(o^mask))) // unknown
	}

	if len(bits) == 1 {
		return bits[0]
	}
	// Multiple values, so we need to wrap with parentheses.
	return "(" + strings.Join(bits, " | ") + ")"
}

// AppendText implements the [encoding.TextAppender] interface
// by encoding its textual representation.
func (o NotifyWatchOpt) AppendText(b []byte) ([]byte, error) {
	return strconv.AppendUint(b, uint64(o), 10), nil
}

// MarshalText implements the [encoding.TextMarshaler] interface
// by encoding its textual representation.
func (o NotifyWatchOpt) MarshalText() (text []byte, err error) {
	return o.AppendText(nil)
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface
// by decoding its textual representation.
func (o *NotifyWatchOpt) UnmarshalText(text []byte) error {
	v, err := strconv.ParseUint(string(text), 10, 64)
	if err != nil {
		return err
	}
	*o = NotifyWatchOpt(v)
	return nil
}

// NotifyRateLimitIncompatibleBits is the set of new-style IPN bus
// subscription bits that cannot be combined with [NotifyRateLimit].
//
// Those bits describe stateful delta streams. Randomly delaying or merging
// messages in those streams would break the consumer's ability to maintain a
// coherent local view.
const NotifyRateLimitIncompatibleBits = NotifyPeerChanges | NotifyNoNetMap | NotifyInitialStatus | NotifyPeerPatches

// ValidateNotifyWatchOpt reports whether mask is a valid WatchIPNBus
// subscription mask.
func ValidateNotifyWatchOpt(mask NotifyWatchOpt) error {
	if mask&NotifyRateLimit != 0 {
		if bad := mask & NotifyRateLimitIncompatibleBits; bad != 0 {
			return fmt.Errorf("NotifyRateLimit is incompatible with new-style IPN bus subscription bits %v", bad)
		}
	}
	return nil
}

// Notify is a communication from a backend (e.g. tailscaled) to a frontend
// (cmd/tailscale, iOS, macOS, Win Tasktray).
// In any given notification, any or all of these may be nil, meaning
// that they have not changed.
// They are JSON-encoded on the wire, despite the lack of struct tags.
type Notify struct {
	_       structs.Incomparable
	Version string // version number of IPN backend

	// SessionID identifies the unique WatchIPNBus session.
	// This field is only set in the first message when requesting
	// NotifyInitialState. Clients must store it on their side as
	// following notifications will not include this field.
	SessionID string `json:",omitzero"`

	// ErrMessage, if non-nil, contains a critical error message.
	// For State InUseOtherUser, ErrMessage is not critical and just contains the details.
	ErrMessage *string

	LoginFinished *empty.Message // non-nil when/if the login process succeeded
	State         *State         // if non-nil, the new or current IPN state
	Prefs         *PrefsView     // if non-nil && Valid, the new or current preferences

	// SelfChange, if non-nil, indicates that this node's own [tailcfg.Node]
	// has changed: addresses, name, key expiry, capabilities, etc. It carries
	// the new self node so reactive consumers (containerboot, kube agents,
	// sniproxy, etc.) can read the current self state without watching the
	// full netmap.
	//
	// Consumers that need additional state (peers, DNS config, packet
	// filter) should react to SelfChange by fetching the full netmap on
	// demand via [LocalClient.NetMap].
	SelfChange *tailcfg.Node `json:",omitzero"`

	// InitialStatus, if non-nil, is the current [ipnstate.Status]. It is
	// only set in the first Notify of a session when the watcher requested
	// [NotifyInitialStatus]. Together with subsequent [Notify.SelfChange]
	// and [Notify.PeerChanges] messages, it lets a watcher stitch together
	// a continuous view of node state without fetching the netmap.
	InitialStatus *ipnstate.Status `json:",omitzero"`

	// NetMap, if non-nil, is the full network map. New consumers should prefer
	// [LocalClient.NetMap] for one-shot fetches and [Notify.SelfChange] /
	// [Notify.PeerChanges] for incremental reactive updates; NetMap on the bus
	// is the legacy path retained for hosts whose GUIs have not yet finished
	// migrating. It is delivered:
	//
	//   - On the initial Notify if the watcher requested
	//     [NotifyInitialNetMap] (any platform).
	//   - On subsequent Notify messages, only when tailscaled is running
	//     on Windows, macOS, or iOS. On Linux and other platforms it is
	//     always nil after the initial notify.
	//
	// Deprecated: this field is only populated on Windows, macOS, and iOS and
	// is slated for removal in favor of [Notify.InitialStatus] +
	// [Notify.SelfChange] / [Notify.PeerChanges], etc, as this field
	// doesn't scale.
	NetMap *netmap.NetworkMap

	// PeerChangedPatch, if non-empty, lists narrow per-field peer patches
	// since the last Notify (currently Online, LastSeen, DERPHome,
	// Endpoints). It mirrors [tailcfg.MapResponse.PeersChangedPatch].
	//
	// Peer additions and any peer change that can't be expressed as a
	// [tailcfg.PeerChange] travel in [Notify.PeersChanged]; peer removals
	// in [Notify.PeersRemoved].
	//
	// Watchers must opt in to receive this field by setting
	// [NotifyPeerPatches]; without that bit (but with [NotifyPeerChanges])
	// the producer promotes each patch into a full-Node entry in
	// [Notify.PeersChanged] instead.
	//
	// The [tailcfg.PeerChange] type may grow more fields over time;
	// consumers that see a [tailcfg.PeerChange] with a field they don't
	// recognize should re-fetch the affected node by NodeID via
	// [LocalClient.PeerByID] (an O(1) lookup) to learn its current value
	// rather than ignoring the change.
	PeerChangedPatch []*tailcfg.PeerChange `json:",omitzero"`

	// PeersChanged, if non-empty, lists peers whose full [tailcfg.Node]
	// has been added or replaced since the last Notify. A node ID may
	// appear here either because it is a brand-new peer or because the
	// control plane sent a fresh full Node for an existing peer when the
	// change wasn't expressible as a [tailcfg.PeerChange] patch (e.g. a
	// CapMap, Addresses, Hostinfo, or Tags change). Consumers should
	// upsert by NodeID.
	//
	// This mirrors [tailcfg.MapResponse.PeersChanged] semantics; peer
	// removals travel in [Notify.PeersRemoved] and narrow per-field
	// patches in [Notify.PeerChanges].
	PeersChanged []*tailcfg.Node `json:",omitzero"`

	// PeersRemoved, if non-empty, lists [tailcfg.NodeID]s that have been
	// removed from the netmap since the last Notify. See
	// [Notify.PeersChanged]. This mirrors
	// [tailcfg.MapResponse.PeersRemoved].
	PeersRemoved []tailcfg.NodeID `json:",omitzero"`

	// UserProfiles, if non-empty, carries [tailcfg.UserProfileView]
	// entries that have been added or updated since the last Notify on
	// this session. Watchers must opt in via [NotifyPeerChanges] or
	// [NotifyPeerPatches]; this field is gated on the same bits as
	// [Notify.PeersChanged] / [Notify.PeerChangedPatch] because its
	// only purpose is to let those consumers resolve the [tailcfg.UserID]
	// referenced by a peer Node.
	//
	// The producer guarantees that any UserID referenced by a peer in
	// a [Notify.PeersChanged] / [Notify.PeerChangedPatch] entry will
	// have its profile delivered either earlier on this same session
	// (e.g. via the initial NetMap or via an earlier Notify carrying
	// UserProfiles) or in this same Notify. A consumer that sees a
	// UserID it doesn't recognize on a session that opted in to
	// peer-change notifications can treat it as a bug; the
	// [LocalClient.UserProfile] LocalAPI fallback exists for sessions
	// that didn't subscribe with the peer-change bits or that need to
	// look up a UserID for any other reason.
	//
	// The values are [tailcfg.UserProfileView] so they share backing
	// memory with the producer's tracking maps; consumers should treat
	// them as read-only and use [tailcfg.UserProfileView.AsStruct] or
	// the per-field accessors to read them.
	UserProfiles map[tailcfg.UserID]tailcfg.UserProfileView `json:",omitzero"`

	// PeerState, if non-empty, carries WireGuard session states keyed by stable
	// node ID. Watchers must opt in via [NotifyPeerWireGuardState].
	PeerState map[tailcfg.StableNodeID]PeerState `json:",omitzero"`

	Engine      *EngineStatus // if non-nil, the new or current wireguard stats
	BrowseToURL *string       // if non-nil, UI should open a browser right now

	// FilesWaiting if non-nil means that files are buffered in
	// the Tailscale daemon and ready for local transfer to the
	// user's preferred storage location.
	//
	// Deprecated: use LocalClient.AwaitWaitingFiles instead.
	FilesWaiting *empty.Message `json:",omitzero"`

	// IncomingFiles, if non-nil, specifies which files are in the
	// process of being received. A nil IncomingFiles means this
	// Notify should not update the state of file transfers. A non-nil
	// but empty IncomingFiles means that no files are in the middle
	// of being transferred.
	//
	// Deprecated: use LocalClient.AwaitWaitingFiles instead.
	IncomingFiles []PartialFile `json:",omitzero"`

	// OutgoingFiles, if non-nil, tracks which files are in the process of
	// being sent via TailDrop, including files that finished, whether
	// successful or failed. This slice is sorted by Started time, then Name.
	OutgoingFiles []*OutgoingFile `json:",omitzero"`

	// LocalTCPPort, if non-nil, informs the UI frontend which
	// (non-zero) localhost TCP port it's listening on.
	// This is currently only used by Tailscale when run in the
	// macOS Network Extension.
	LocalTCPPort *uint16 `json:",omitzero"`

	// ClientVersion, if non-nil, describes whether a client version update
	// is available.
	ClientVersion *tailcfg.ClientVersion `json:",omitzero"`

	// DriveShares tracks the full set of current DriveShares that we're
	// publishing. Some client applications, like the MacOS and Windows clients,
	// will listen for updates to this and handle serving these shares under
	// the identity of the unprivileged user that is running the application. A
	// nil value here means that we're not broadcasting shares information, an
	// empty value means that there are no shares.
	DriveShares views.SliceView[*drive.Share, drive.ShareView]

	// Health is the last-known health state of the backend. When this field is
	// non-nil, a change in health verified, and the API client should surface
	// any changes to the user in the UI.
	Health *health.State `json:",omitzero"`

	// SuggestedExitNode, if non-nil, is the node that the backend has determined to
	// be the best exit node for the current network conditions.
	SuggestedExitNode *tailcfg.StableNodeID `json:",omitzero"`

	// Policy, if non-nil, is the effective policy snapshot for the
	// connected user. It is scoped per-user: per-user policy settings
	// are merged with device-wide settings, with device-wide taking
	// precedence. Sent initially when [NotifySysPolicyChanges] is set,
	// and on change thereafter.
	Policy *policyclient.PolicySnapshot `json:",omitzero"`

	// type is mirrored in xcode/IPN/Core/LocalAPI/Model/LocalAPIModel.swift
}

// PeerWireGuardState is the WireGuard session state for a peer.
//
// It JSON-marshals as a lowercase string (e.g. "handshake", "established")
// rather than its integer value, so the wire format does not depend on the
// numeric constants below.
type PeerWireGuardState uint8

const (
	PeerWireGuardStateNone        PeerWireGuardState = 0
	PeerWireGuardStateHandshake   PeerWireGuardState = 1
	PeerWireGuardStateEstablished PeerWireGuardState = 2
	PeerWireGuardStateExpired     PeerWireGuardState = 3
)

// String returns the lowercase string form of s used by [PeerWireGuardState.MarshalText].
func (s PeerWireGuardState) String() string {
	switch s {
	case PeerWireGuardStateNone:
		return "none"
	case PeerWireGuardStateHandshake:
		return "handshake"
	case PeerWireGuardStateEstablished:
		return "established"
	case PeerWireGuardStateExpired:
		return "expired"
	}
	return fmt.Sprintf("PeerWireGuardState(%d)", uint8(s))
}

// MarshalText implements [encoding.TextMarshaler].
func (s PeerWireGuardState) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (s *PeerWireGuardState) UnmarshalText(b []byte) error {
	switch string(b) {
	case "none":
		*s = PeerWireGuardStateNone
	case "handshake":
		*s = PeerWireGuardStateHandshake
	case "established":
		*s = PeerWireGuardStateEstablished
	case "expired":
		*s = PeerWireGuardStateExpired
	default:
		return fmt.Errorf("unknown PeerWireGuardState %q", b)
	}
	return nil
}

// PeerState is the per-peer WireGuard session state delivered in
// [Notify.PeerState].
type PeerState struct {
	// PeerWireGuardState is the current WireGuard session state for the peer.
	PeerWireGuardState PeerWireGuardState

	// PeerWireGuardStateAt is the wall-clock time at which the peer entered
	// [PeerState.PeerWireGuardState], as observed by tailscaled.
	// It is tracked by [LocalBackend] even when no watchers are subscribed,
	// so a later subscriber's initial snapshot reflects the true transition
	// time rather than the subscription time.
	PeerWireGuardStateAt time.Time
}

func (n Notify) String() string {
	var sb strings.Builder
	sb.WriteString("Notify{")
	if n.ErrMessage != nil {
		fmt.Fprintf(&sb, "err=%q ", *n.ErrMessage)
	}
	if n.LoginFinished != nil {
		sb.WriteString("LoginFinished ")
	}
	if n.State != nil {
		fmt.Fprintf(&sb, "state=%v ", *n.State)
	}
	if n.Prefs != nil && n.Prefs.Valid() {
		fmt.Fprintf(&sb, "%v ", n.Prefs.Pretty())
	}
	if n.SelfChange != nil {
		fmt.Fprintf(&sb, "SelfChange(%v) ", n.SelfChange.StableID)
	}
	if n.PeerChangedPatch != nil {
		fmt.Fprintf(&sb, "PeerChangedPatch(%d) ", len(n.PeerChangedPatch))
	}
	if len(n.PeerState) > 0 {
		fmt.Fprintf(&sb, "PeerState(%d) ", len(n.PeerState))
	}
	if n.Engine != nil {
		fmt.Fprintf(&sb, "wg=%v ", *n.Engine)
	}
	if n.BrowseToURL != nil {
		sb.WriteString("URL=<...> ")
	}
	if n.FilesWaiting != nil {
		sb.WriteString("FilesWaiting ")
	}
	if len(n.IncomingFiles) != 0 {
		sb.WriteString("IncomingFiles ")
	}
	if n.LocalTCPPort != nil {
		fmt.Fprintf(&sb, "tcpport=%v ", n.LocalTCPPort)
	}
	if n.Health != nil {
		sb.WriteString("Health{...} ")
	}
	if n.SuggestedExitNode != nil {
		fmt.Fprintf(&sb, "SuggestedExitNode=%v ", *n.SuggestedExitNode)
	}

	s := sb.String()
	if s == "Notify{" {
		return "Notify{}"
	} else {
		return s[0:len(s)-1] + "}"
	}
}

// PartialFile represents an in-progress incoming file transfer.
type PartialFile struct {
	Name         string    // e.g. "foo.jpg"
	Started      time.Time // time transfer started
	DeclaredSize int64     // or -1 if unknown
	Received     int64     // bytes copied thus far

	// PartialPath is set non-empty in "direct" file mode to the
	// in-progress '*.partial' file's path when the peerapi isn't
	// being used; see LocalBackend.SetDirectFileRoot.
	PartialPath string `json:",omitempty"`
	FinalPath   string `json:",omitempty"`

	// Done is set in "direct" mode when the partial file has been
	// closed and is ready for the caller to rename away the
	// ".partial" suffix.
	Done bool `json:",omitempty"`
}

// OutgoingFile represents an in-progress outgoing file transfer.
type OutgoingFile struct {
	ID           string               `json:",omitempty"` // unique identifier for this transfer (a type 4 UUID)
	PeerID       tailcfg.StableNodeID `json:",omitempty"` // identifier for the peer to which this is being transferred
	Name         string               `json:",omitempty"` // e.g. "foo.jpg"
	Started      time.Time            // time transfer started
	DeclaredSize int64                // or -1 if unknown
	Sent         int64                // bytes copied thus far
	Finished     bool                 // indicates whether or not the transfer finished
	Succeeded    bool                 // for a finished transfer, indicates whether or not it was successful
}

// StateKey is an opaque identifier for a set of LocalBackend state
// (preferences, private keys, etc.). It is also used as a key for
// the various LoginProfiles that the instance may be signed into.
//
// Additionally, the StateKey can be debug setting name:
//
//   - "_debug_magicsock_until" with value being a unix timestamp stringified
//   - "_debug_<component>_until" with value being a unix timestamp stringified
type StateKey string

// DebuggableComponents is a list of components whose debugging can be turned on
// and off individually using the tailscale debug command.
var DebuggableComponents = []string{
	"magicsock",
	"sockstats",
	"syspolicy",
}

type Options struct {
	// FrontendLogID is the public logtail id used by the frontend.
	FrontendLogID string
	// UpdatePrefs, if provided, overrides the Prefs already stored in the
	// backend state, *except* for the Persist member.
	//
	// TODO(apenwarr): Rename this to Prefs, and possibly move Prefs.Persist
	// elsewhere entirely (as it always should have been).
	UpdatePrefs *Prefs
	// AuthKey is an optional node auth key used to authorize a
	// new node key without user interaction.
	AuthKey string
}
