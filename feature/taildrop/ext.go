// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/cmd/tailscaled/tailscaledhooks"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/feature/taildrop/taildroptype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/localapi"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstime"
	"tailscale.com/types/empty"
	"tailscale.com/types/logger"
	"tailscale.com/util/osshare"
	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/syspolicy/ptype"
)

func init() {
	if !feature.Register("taildrop") {
		return
	}
	ipnext.RegisterExtension("taildrop", newExtension)
	ipnlocal.RegisterPeerAPIHandler("/v0/put/", handlePeerPut)
	localapi.Register("file-put/", serveFilePut)
	localapi.Register("files/", serveFiles)
	localapi.Register("file-targets", serveFileTargets)

	if runtime.GOOS == "windows" {
		tailscaledhooks.UninstallSystemDaemonWindows.Add(func() {
			// Remove file sharing from Windows shell.
			osshare.SetFileSharingEnabled(false, logger.Discard)
		})
	}
}

func newExtension(logf logger.Logf, b ipnext.SafeBackend) (ipnext.Extension, error) {
	e := &Extension{
		sb:         b,
		polc:       b.Sys().PolicyClientOrDefault(),
		stateStore: b.Sys().StateStore.Get(),
		logf:       logger.WithPrefix(logf, "taildrop: "),
	}
	e.setPlatformDefaultDirectFileRoot()
	return e, nil
}

// Extension implements Taildrop.
type Extension struct {
	logf       logger.Logf
	sb         ipnext.SafeBackend
	stateStore ipn.StateStore
	polc       policyclient.Client
	host       ipnext.Host // from Init

	// directFileRoot, if non-empty, means to write received files
	// directly to this directory, without staging them in an
	// intermediate buffered directory for "pick-up" later. If
	// empty, the files are received in a daemon-owned location
	// and the localapi is used to enumerate, download, and delete
	// them. This is used on macOS where the GUI lifetime is the
	// same as the Network Extension lifetime and we can thus avoid
	// double-copying files by writing them to the right location
	// immediately.
	// It's also used on several NAS platforms (Synology, TrueNAS, etc)
	// but in that case DoFinalRename is also set true, which moves the
	// *.partial file to its final name on completion.
	directFileRoot string

	// FileOps abstracts platform-specific file operations needed for file transfers.
	// This is currently being used for Android to use the Storage Access Framework.
	fileOps FileOps

	nodeBackendForTest ipnext.NodeBackend // if non-nil, pretend we're this node state for tests

	// sentConsent caches the consent tokens this node has obtained from peers
	// for its own outbound transfers, keyed by [outboundConsentKey].
	sentConsent outboundConsentCache

	// noConsentPeers records, per peer, when to stop believing that the peer
	// doesn't require consent. See [senderNoConsentTTL].
	noConsentPeers syncs.Map[tailcfg.StableNodeID, time.Time]

	mu                    sync.Mutex // Lock order: lb.mu > e.mu
	backendState          ipn.State
	selfUID               tailcfg.UserID
	allowExternalTaildrop atomic.Bool
	capFileSharing        bool
	fileWaiters           set.HandleSet[context.CancelFunc] // of wake-up funcs
	mgr                   atomic.Pointer[manager]           // mutex held to write; safe to read without lock;
	// outgoingFiles keeps track of Taildrop outgoing files keyed to their OutgoingFile.ID
	outgoingFiles map[string]*ipn.OutgoingFile
}

func (e *Extension) Name() string {
	return "taildrop"
}

func (e *Extension) Init(h ipnext.Host) error {
	e.host = h

	osshare.SetFileSharingEnabled(false, e.logf)

	h.Hooks().ProfileStateChange.Add(e.onChangeProfile)
	h.Hooks().OnSelfChange.Add(e.onSelfChange)
	h.Hooks().MutateNotifyLocked.Add(e.setNotifyFilesWaiting)
	h.Hooks().InitialNotifyLocked.Add(e.initialNotify)
	h.Hooks().SetPeerStatus.Add(e.setPeerStatus)
	h.Hooks().BackendStateChange.Add(e.onBackendStateChange)

	// TODO(nickkhyl): remove this after the profileManager refactoring.
	// See tailscale/tailscale#15974.
	// This same workaround appears in feature/portlist/portlist.go.
	profile, prefs := h.Profiles().CurrentProfileState()
	e.onChangeProfile(profile, prefs, false)
	return nil
}

func (e *Extension) onBackendStateChange(st ipn.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.backendState = st
}

func (e *Extension) onSelfChange(self tailcfg.NodeView) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.selfUID = 0
	if self.Valid() {
		e.selfUID = self.User()
	}
	e.capFileSharing = self.Valid() && self.CapMap().Contains(nodecap.FileSharing)
	osshare.SetFileSharingEnabled(e.capFileSharing, e.logf)
}

func (e *Extension) setMgrLocked(mgr *manager) {
	if old := e.mgr.Swap(mgr); old != nil {
		old.Shutdown()
	}
	e.sendConsentNotify()
}

func (e *Extension) onChangeProfile(profile ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !sameNode {
		e.sentConsent.Clear()
		e.noConsentPeers.Clear()
	}
	allowExternal := prefs.Valid() && prefs.AllowExternalTaildrop()
	previous := e.allowExternalTaildrop.Swap(allowExternal)
	if !sameNode || previous != allowExternal {
		e.logf("consent settings: allow-external=%v, force-own=%v", allowExternal, e.forceOwnConsent())
	}
	uid := profile.UserProfile().ID()
	activeLogin := profile.UserProfile().LoginName()

	if uid == 0 {
		e.setMgrLocked(nil)
		e.outgoingFiles = nil
		return
	}

	if sameNode && e.manager() != nil {
		return
	}

	// Use the provided [FileOps] implementation (typically for SAF access on Android),
	// or create an [fsFileOps] instance rooted at fileRoot.
	//
	// A non-nil [FileOps] also implies that we are in DirectFileMode.
	fops := e.fileOps
	isDirectFileMode := fops != nil
	if fops == nil {
		var fileRoot string
		if fileRoot, isDirectFileMode = e.fileRoot(uid, activeLogin); fileRoot == "" {
			e.logf("no Taildrop directory configured")
			e.setMgrLocked(nil)
			return
		}

		var err error
		if fops, err = newFileOps(fileRoot); err != nil {
			e.logf("taildrop: cannot create FileOps: %v", err)
			e.setMgrLocked(nil)
			return
		}
	}

	e.setMgrLocked(managerOptions{
		Logf:                  e.logf,
		Clock:                 tstime.DefaultClock{Clock: e.sb.Clock()},
		State:                 e.stateStore,
		DirectFileMode:        isDirectFileMode,
		fileOps:               fops,
		SendFileNotify:        e.sendFileNotify,
		ConsentForOwnDevices:  e.forceOwnConsent,
		AllowExternalTaildrop: e.externalReceiveAllowed,
		NotifyConsent:         e.sendConsentNotify,
	}.New())
}

// fileRoot returns where to store Taildrop files for the given user and whether
// to write received files directly to this directory, without staging them in
// an intermediate buffered directory for "pick-up" later.
//
// It is safe to call this with b.mu held but it does not require it or acquire
// it itself.
func (e *Extension) fileRoot(uid tailcfg.UserID, activeLogin string) (root string, isDirect bool) {
	if v := e.directFileRoot; v != "" {
		return v, true
	}
	varRoot := e.sb.TailscaleVarRoot()
	if varRoot == "" {
		e.logf("Taildrop disabled; no state directory")
		return "", false
	}

	if activeLogin == "" {
		e.logf("taildrop: no active login; can't select a target directory")
		return "", false
	}

	baseDir := fmt.Sprintf("%s-uid-%d",
		strings.ReplaceAll(activeLogin, "@", "-"),
		uid)
	return filepath.Join(varRoot, "files", baseDir), false
}

// hasCapFileSharing reports whether the current node has the file sharing
// capability.
func (e *Extension) hasCapFileSharing() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.capFileSharing
}

// manager returns the active Manager, or nil.
//
// Methods on a nil Manager are safe to call.
func (e *Extension) manager() *manager {
	return e.mgr.Load()
}

func (e *Extension) Clock() tstime.Clock {
	return e.sb.Clock()
}

func (e *Extension) Shutdown() error {
	e.sentConsent.Clear()
	e.manager().Shutdown() // no-op on nil receiver
	return nil
}

func (e *Extension) sendFileNotify() {
	mgr := e.manager()
	if mgr == nil {
		return
	}

	var n ipn.Notify

	e.mu.Lock()
	for _, wakeWaiter := range e.fileWaiters {
		wakeWaiter()
	}
	n.IncomingFiles = mgr.IncomingFiles()
	e.mu.Unlock()

	e.host.SendNotifyAsync(n)
}

// sendConsentNotify tells watchers the current set of inbound transfers
// awaiting the device owner's approval.
//
// Runtime events carry full snapshots. initialNotify supplies the corresponding
// baseline to newly connected watchers, including when the set is empty.
func (e *Extension) sendConsentNotify() {
	if e.host == nil {
		return
	}
	e.host.SendNotifyAsync(ipn.Notify{
		TaildropConsentRequests: e.ConsentRequests(),
	})
}

// ConsentRequests returns the inbound transfers awaiting the device owner's
// approval, oldest first.
func (e *Extension) ConsentRequests() []taildroptype.ConsentRequest {
	return e.manager().pendingConsentRequests()
}

// RespondToConsent applies the device owner's decision to the pending consent
// request with the given ID.
func (e *Extension) RespondToConsent(id string, allow bool) error {
	if allow && !e.externalPolicyAllowed() {
		return errExternalTaildropPolicy
	}
	return e.manager().resolveConsent(id, allow)
}

func (e *Extension) setNotifyFilesWaiting(n *ipn.Notify) {
	// Refresh consent snapshots when the queued event is actually delivered,
	// so an older asynchronous snapshot cannot resurrect a dismissed prompt.
	if n.TaildropConsentRequests != nil {
		n.TaildropConsentRequests = e.ConsentRequests()
	}
	if e.manager().HasFilesWaiting() {
		n.FilesWaiting = &empty.Message{}
	}
}

func (e *Extension) initialNotify(mask ipn.NotifyWatchOpt, n *ipn.Notify) {
	if mask&(ipn.NotifyInitialState|ipn.NotifyInitialTaildropConsentRequests) != 0 {
		n.TaildropConsentRequests = e.ConsentRequests()
	}
}

func (e *Extension) setPeerStatus(ps *ipnstate.PeerStatus, p tailcfg.NodeView, nb ipnext.NodeBackend) {
	ps.TaildropTarget = e.taildropTargetStatus(p, nb)
}

func (e *Extension) removeFileWaiter(handle set.Handle) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.fileWaiters, handle)
}

func (e *Extension) addFileWaiter(wakeWaiter context.CancelFunc) set.Handle {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fileWaiters.Add(wakeWaiter)
}

func (e *Extension) WaitingFiles() ([]apitype.WaitingFile, error) {
	return e.manager().WaitingFiles()
}

// AwaitWaitingFiles is like WaitingFiles but blocks while ctx is not done,
// waiting for any files to be available.
//
// On return, exactly one of the results will be non-empty or non-nil,
// respectively.
func (e *Extension) AwaitWaitingFiles(ctx context.Context) ([]apitype.WaitingFile, error) {
	if ff, err := e.WaitingFiles(); err != nil || len(ff) > 0 {
		return ff, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for {
		gotFile, gotFileCancel := context.WithCancel(context.Background())
		defer gotFileCancel()

		handle := e.addFileWaiter(gotFileCancel)
		defer e.removeFileWaiter(handle)

		// Now that we've registered ourselves, check again, in case
		// of race. Otherwise there's a small window where we could
		// miss a file arrival and wait forever.
		if ff, err := e.WaitingFiles(); err != nil || len(ff) > 0 {
			return ff, err
		}

		select {
		case <-gotFile.Done():
			if ff, err := e.WaitingFiles(); err != nil || len(ff) > 0 {
				return ff, err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (e *Extension) DeleteFile(name string) error {
	return e.manager().DeleteFile(name)
}

func (e *Extension) OpenFile(name string) (rc io.ReadCloser, size int64, err error) {
	return e.manager().OpenFile(name)
}

func (e *Extension) nodeBackend() ipnext.NodeBackend {
	if e.nodeBackendForTest != nil {
		return e.nodeBackendForTest
	}
	return e.host.NodeBackend()
}

// Forces the consent flow on all transfers, even to self-owned nodes.
// This is used for testing and development where envKnobs aren't available.
const forceConsentOverride = false

func forceConsent() bool {
	return forceConsentOverride || envknob.ForceTaildropConsentForEverything()
}

// forceOwnConsent enables the development-only same-user consent flow.
// Both send and receive paths must apply the same opt-in gate.
func (e *Extension) forceOwnConsent() bool {
	return forceConsent() && e.allowExternalTaildrop.Load()
}

// shouldRequestConsent includes same-user peers when testing the consent flow.
func (e *Extension) shouldRequestConsent(peer tailcfg.StableNodeID) bool {
	return e.forceOwnConsent() || !e.isOwnPeer(peer)
}

// FileTargets lists nodes that the current node can send files to.
func (e *Extension) FileTargets() ([]*apitype.FileTarget, error) {
	var ret []*apitype.FileTarget

	e.mu.Lock()
	st := e.backendState
	e.mu.Unlock()

	if st != ipn.Running {
		return nil, errors.New("not connected to the tailnet")
	}
	if !e.hasCapFileSharing() {
		return nil, errors.New("file sharing not enabled by Tailscale admin")
	}
	nb := e.nodeBackend()

	// Offer legacy self-owned peers and consent-capable cross-user peers.
	peers := nb.AppendMatchingPeers(nil, func(p tailcfg.NodeView) bool {
		return e.eligibleTarget(p, nb) && p.Hostinfo().OS() != "tvOS"
	})
	for _, p := range peers {
		peerAPI := nb.PeerAPIBase(p)
		if peerAPI == "" {
			continue
		}
		ret = append(ret, &apitype.FileTarget{
			Node:       p.AsStruct(),
			PeerAPIURL: peerAPI,
		})
	}
	slices.SortFunc(ret, func(a, b *apitype.FileTarget) int {
		return cmp.Compare(a.Node.Name, b.Node.Name)
	})
	return ret, nil
}

// peerAPIURLFor returns the PeerAPI base URL of a node this one may send files
// to, or an error if it isn't a valid Taildrop target.
func (e *Extension) peerAPIURLFor(peerID tailcfg.StableNodeID) (*url.URL, error) {
	fts, err := e.FileTargets()
	if err != nil {
		return nil, err
	}
	for _, ft := range fts {
		if ft.Node.StableID == peerID {
			return url.Parse(ft.PeerAPIURL)
		}
	}
	return nil, errors.New("node not found")
}

func (e *Extension) taildropTargetStatus(p tailcfg.NodeView, nb ipnext.NodeBackend) ipnstate.TaildropTargetStatus {
	e.mu.Lock()
	st := e.backendState
	selfUID := e.selfUID
	capFileSharing := e.capFileSharing
	e.mu.Unlock()

	if st != ipn.Running {
		return ipnstate.TaildropTargetIpnStateNotRunning
	}

	if !capFileSharing {
		return ipnstate.TaildropTargetMissingCap
	}
	if !p.Valid() {
		return ipnstate.TaildropTargetNoPeerInfo
	}
	if !sameUserUntagged(p, nb.Self(), selfUID) && !e.externalPolicyAllowed() {
		return ipnstate.TaildropTargetPolicyDenied
	}
	if !e.eligibleTarget(p, nb) {
		return ipnstate.TaildropTargetMissingCap
	}
	if !p.Online().Get() {
		return ipnstate.TaildropTargetOffline
	}
	if p.Hostinfo().OS() == "tvOS" {
		return ipnstate.TaildropTargetUnsupportedOS
	}
	if !nb.PeerHasPeerAPI(p) {
		return ipnstate.TaildropTargetNoPeerAPI
	}
	if e.forceOwnConsent() || !sameUserUntagged(p, nb.Self(), selfUID) {
		return ipnstate.TaildropTargetConsentRequired
	}
	return ipnstate.TaildropTargetAvailable
}

// updateOutgoingFiles merges updates into e.outgoingFiles and emits an
// ipn.Notify.
func (e *Extension) updateOutgoingFiles(updates map[string]ipn.OutgoingFile) {
	e.mu.Lock()
	if e.outgoingFiles == nil {
		e.outgoingFiles = make(map[string]*ipn.OutgoingFile, len(updates))
	}
	for id, f := range updates {
		e.outgoingFiles[id] = &f
	}
	outgoingFiles := make([]*ipn.OutgoingFile, 0, len(e.outgoingFiles))
	for _, file := range e.outgoingFiles {
		outgoingFiles = append(outgoingFiles, file)
	}
	e.mu.Unlock()
	slices.SortFunc(outgoingFiles, func(a, b *ipn.OutgoingFile) int {
		t := a.Started.Compare(b.Started)
		if t != 0 {
			return t
		}
		return strings.Compare(a.Name, b.Name)
	})

	e.host.SendNotifyAsync(ipn.Notify{OutgoingFiles: outgoingFiles})
}

// eligibleTarget preserves legacy same-user transfers, but requires consent
// protocol and accept-flow UI support for other users and tagged endpoints.
// Unsigned nodes cannot participate.
func (e *Extension) eligibleTarget(p tailcfg.NodeView, nb ipnext.NodeBackend) bool {
	self := nb.Self()
	if !p.Valid() || p.UnsignedPeerAPIOnly() {
		return false
	}
	e.mu.Lock()
	uid := e.selfUID
	e.mu.Unlock()
	if sameUserUntagged(p, self, uid) {
		return true
	}
	if !e.externalPolicyAllowed() || !capVerSupportsConsentProtocol(p.Cap()) || !p.Hostinfo().Valid() {
		return false
	}
	switch p.Hostinfo().OS() {
	case "macOS", "iOS", "darwin":
		return capVerSupportsAppleConsentUI(p.Cap())
	case "windows":
		return capVerSupportsWindowsConsentUI(p.Cap())
	case "android":
		return capVerSupportsAndroidConsentUI(p.Cap())
	case "tvOS", "":
		return false
	default:
		return capVerSupportsCLIConsentUI(p.Cap())
	}
}

// capVerSupportsConsentProtocol reports whether the backend implements the
// Taildrop consent protocol.
func capVerSupportsConsentProtocol(v tailcfg.CapabilityVersion) bool {
	// Assign the capability version when the consent flow is enabled.
	return false
}

// capVerSupportsAppleConsentUI reports whether macOS and iOS clients include
// the accept UI.
func capVerSupportsAppleConsentUI(v tailcfg.CapabilityVersion) bool {
	// TODO: bump/set the minimum capability version when the Apple accept UI ships.
	return false
}

// capVerSupportsWindowsConsentUI reports whether Windows clients include the
// accept UI.
func capVerSupportsWindowsConsentUI(v tailcfg.CapabilityVersion) bool {
	// TODO: bump/set the minimum capability version when the Windows accept UI ships.
	return false
}

// capVerSupportsAndroidConsentUI reports whether Android clients include the
// accept UI.
func capVerSupportsAndroidConsentUI(v tailcfg.CapabilityVersion) bool {
	// TODO: bump/set the minimum capability version when the Android accept UI ships.
	return false
}

// capVerSupportsCLIConsentUI reports whether CLI clients include the accept
// flow.
func capVerSupportsCLIConsentUI(v tailcfg.CapabilityVersion) bool {
	// Assign the capability version when the consent flow is enabled.
	return false
}

func (e *Extension) isOwnPeer(peer tailcfg.StableNodeID) bool {
	e.mu.Lock()
	uid := e.selfUID
	e.mu.Unlock()
	nb := e.nodeBackend()
	self := nb.Self()
	peers := nb.AppendMatchingPeers(nil, func(p tailcfg.NodeView) bool {
		return p.StableID() == peer && sameUserUntagged(p, self, uid)
	})
	return len(peers) != 0
}

// sameUserUntagged identifies transfers eligible for implicit consent.
// A tag at either endpoint requires explicit consent, even if user IDs match.
func sameUserUntagged(peer, self tailcfg.NodeView, uid tailcfg.UserID) bool {
	return peer.User() == uid && !peer.IsTagged() && (!self.Valid() || !self.IsTagged())
}

var errExternalTaildropPolicy = errors.New("cross-user Taildrop is disabled by IT policy")

// externalPolicyAllowed distinguishes a managed prohibition from the receive
// opt-in preference: an unset policy must not prevent outbound transfers.
func (e *Extension) externalPolicyAllowed() bool {
	if e.polc == nil {
		return true
	}
	option, err := e.polc.GetPreferenceOption(pkey.AllowExternalTaildrop, ptype.ShowChoiceByPolicy)
	return err == nil && option != ptype.NeverByPolicy
}

func (e *Extension) externalReceiveAllowed() bool {
	return e.externalPolicyAllowed() && e.allowExternalTaildrop.Load()
}

func (e *Extension) checkSendPolicy(peer tailcfg.StableNodeID) error {
	if !e.externalPolicyAllowed() && !e.isOwnPeer(peer) {
		return errExternalTaildropPolicy
	}
	return nil
}
