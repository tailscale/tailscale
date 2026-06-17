// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"crypto/tls"
	"io"
	"iter"
	"net"
	"net/http"
	"net/netip"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/drive"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/routecheck"
	"tailscale.com/net/udprelay/status"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/appctype"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/syspolicy/setting"
)

// localClientI abstracts the [local.Client] LocalAPI surface so that CLI
// commands can be unit-tested with a mock. It enumerates every exported method
// of [local.Client]; *local.Client satisfies it (asserted where it is returned
// from localClientFromContext).
//
// The mockLocalClient used in tests is generated from this interface by
// mockery; regenerate it after changing this interface.
//
//go:generate go run github.com/vektra/mockery/v2@v2.53.4
type localClientI interface {
	AwaitWaitingFiles(ctx context.Context, d time.Duration) ([]apitype.WaitingFile, error)
	BugReport(ctx context.Context, note string) (string, error)
	BugReportWithOpts(ctx context.Context, opts local.BugReportOpts) (string, error)
	CertDomains(ctx context.Context) ([]string, error)
	CertPair(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error)
	CertPairWithValidity(ctx context.Context, domain string, minValidity time.Duration) (certPEM, keyPEM []byte, err error)
	CheckIPForwarding(ctx context.Context) error
	CheckPrefs(ctx context.Context, p *ipn.Prefs) error
	CheckSOMarkInUse(ctx context.Context) (bool, error)
	CheckUDPGROForwarding(ctx context.Context) error
	CheckUpdate(ctx context.Context) (*tailcfg.ClientVersion, error)
	CurrentDERPMap(ctx context.Context) (*tailcfg.DERPMap, error)
	DNSConfig(ctx context.Context) (*tailcfg.DNSConfig, error)
	DaemonMetrics(ctx context.Context) ([]byte, error)
	DebugAction(ctx context.Context, action string) error
	DebugActionBody(ctx context.Context, action string, rbody io.Reader) error
	DebugDERPRegion(ctx context.Context, regionIDOrCode string) (*ipnstate.DebugDERPRegionReport, error)
	DebugPacketFilterRules(ctx context.Context) ([]tailcfg.FilterRule, error)
	DebugPeerRelaySessions(ctx context.Context) (*status.ServerStatus, error)
	DebugPortmap(ctx context.Context, opts *local.DebugPortmapOpts) (io.ReadCloser, error)
	DebugResultJSON(ctx context.Context, action string) (any, error)
	DebugSetExpireIn(ctx context.Context, d time.Duration) error
	DeleteProfile(ctx context.Context, profile ipn.ProfileID) error
	DeleteWaitingFile(ctx context.Context, baseName string) error
	DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error)
	DisconnectControl(ctx context.Context) error
	DoLocalRequest(req *http.Request) (*http.Response, error)
	DriveSetServerAddr(ctx context.Context, addr string) error
	DriveShareList(ctx context.Context) ([]*drive.Share, error)
	DriveShareRemove(ctx context.Context, name string) error
	DriveShareRename(ctx context.Context, oldName, newName string) error
	DriveShareSet(ctx context.Context, share *drive.Share) error
	EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error)
	EventBusGraph(ctx context.Context) ([]byte, error)
	EventBusQueues(ctx context.Context) ([]byte, error)
	ExpandSNIName(ctx context.Context, name string) (fqdn string, ok bool)
	FileTargets(ctx context.Context) ([]apitype.FileTarget, error)
	GetAppConnectorRouteInfo(ctx context.Context) (appctype.RouteInfo, error)
	GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error)
	GetDNSOSConfig(ctx context.Context) (*apitype.DNSOSConfig, error)
	GetEffectivePolicy(ctx context.Context, scope setting.PolicyScope) (*setting.Snapshot, error)
	GetPrefs(ctx context.Context) (*ipn.Prefs, error)
	GetServeConfig(ctx context.Context) (*ipn.ServeConfig, error)
	GetServices(ctx context.Context) (map[tailcfg.ServiceName]tailcfg.ServiceDetails, error)
	GetWaitingFile(ctx context.Context, baseName string) (rc io.ReadCloser, size int64, err error)
	Goroutines(ctx context.Context) ([]byte, error)
	IDToken(ctx context.Context, aud string) (*tailcfg.TokenResponse, error)
	IncrementCounter(ctx context.Context, name string, delta int) error
	IncrementGauge(ctx context.Context, name string, delta int) error
	Logout(ctx context.Context) error
	NetworkLockAffectedSigs(ctx context.Context, keyID tkatype.KeyID) ([]tkatype.MarshaledSignature, error)
	NetworkLockCosignRecoveryAUM(ctx context.Context, aum tka.AUM) ([]byte, error)
	NetworkLockDisable(ctx context.Context, secret []byte) error
	NetworkLockForceLocalDisable(ctx context.Context) error
	NetworkLockGenRecoveryAUM(ctx context.Context, removeKeys []tkatype.KeyID, forkFrom tka.AUMHash) ([]byte, error)
	NetworkLockInit(ctx context.Context, keys []tka.Key, disablementValues [][]byte, supportDisablement []byte) (*ipnstate.TailnetLockStatus, error)
	NetworkLockLog(ctx context.Context, maxEntries int) ([]ipnstate.TailnetLockUpdate, error)
	NetworkLockModify(ctx context.Context, addKeys, removeKeys []tka.Key) error
	NetworkLockSign(ctx context.Context, nodeKey key.NodePublic, rotationPublic []byte) error
	NetworkLockStatus(ctx context.Context) (*ipnstate.TailnetLockStatus, error)
	NetworkLockSubmitRecoveryAUM(ctx context.Context, aum tka.AUM) error
	NetworkLockVerifySigningDeeplink(ctx context.Context, url string) (*tka.DeeplinkValidationResult, error)
	NetworkLockWrapPreauthKey(ctx context.Context, preauthKey string, tkaKey key.NLPrivate) (string, error)
	PeerByID(ctx context.Context, id tailcfg.NodeID) (*tailcfg.Node, error)
	Ping(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType) (*ipnstate.PingResult, error)
	PingWithOpts(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType, opts local.PingOpts) (*ipnstate.PingResult, error)
	Pprof(ctx context.Context, pprofType string, sec int) ([]byte, error)
	ProfileStatus(ctx context.Context) (current ipn.LoginProfile, all []ipn.LoginProfile, err error)
	PushFile(ctx context.Context, target tailcfg.StableNodeID, size int64, name string, r io.Reader) error
	QueryDNS(ctx context.Context, name string, queryType string) (bytes []byte, resolvers []*dnstype.Resolver, err error)
	QueryFeature(ctx context.Context, feature string) (*tailcfg.QueryFeatureResponse, error)
	QueryOptionalFeatures(ctx context.Context) (*apitype.OptionalFeatures, error)
	ReloadConfig(ctx context.Context) (ok bool, err error)
	ReloadEffectivePolicy(ctx context.Context, scope setting.PolicyScope) (*setting.Snapshot, error)
	RouteCheck(ctx context.Context) (*routecheck.Report, error)
	RouteCheckProbe(ctx context.Context) (*routecheck.Report, error)
	SetComponentDebugLogging(ctx context.Context, component string, d time.Duration) error
	SetDNS(ctx context.Context, name, value string) error
	SetDevStoreKeyValue(ctx context.Context, key, value string) error
	SetGauge(ctx context.Context, name string, value int) error
	SetServeConfig(ctx context.Context, config *ipn.ServeConfig) error
	SetUDPGROForwarding(ctx context.Context) error
	SetUseExitNode(ctx context.Context, on bool) error
	ShutdownTailscaled(ctx context.Context) error
	Start(ctx context.Context, opts ipn.Options) error
	StartLoginInteractive(ctx context.Context) error
	Status(ctx context.Context) (*ipnstate.Status, error)
	StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error)
	StreamBusEvents(ctx context.Context) iter.Seq2[eventbus.DebugEvent, error]
	StreamDebugCapture(ctx context.Context) (io.ReadCloser, error)
	SuggestExitNode(ctx context.Context) (apitype.ExitNodeSuggestionResponse, error)
	SwitchProfile(ctx context.Context, profile ipn.ProfileID) error
	SwitchToEmptyProfile(ctx context.Context) error
	TailDaemonLogs(ctx context.Context) (io.Reader, error)
	TailnetLockAffectedSigs(ctx context.Context, keyID tkatype.KeyID) ([]tkatype.MarshaledSignature, error)
	TailnetLockCosignRecoveryAUM(ctx context.Context, aum tka.AUM) ([]byte, error)
	TailnetLockDisable(ctx context.Context, secret []byte) error
	TailnetLockForceLocalDisable(ctx context.Context) error
	TailnetLockGenRecoveryAUM(ctx context.Context, removeKeys []tkatype.KeyID, forkFrom tka.AUMHash) ([]byte, error)
	TailnetLockInit(ctx context.Context, keys []tka.Key, disablementValues [][]byte, supportDisablement []byte) (*ipnstate.TailnetLockStatus, error)
	TailnetLockLog(ctx context.Context, maxEntries int) ([]ipnstate.TailnetLockUpdate, error)
	TailnetLockModify(ctx context.Context, addKeys, removeKeys []tka.Key) error
	TailnetLockSign(ctx context.Context, nodeKey key.NodePublic, rotationPublic []byte) error
	TailnetLockStatus(ctx context.Context) (*ipnstate.TailnetLockStatus, error)
	TailnetLockSubmitRecoveryAUM(ctx context.Context, aum tka.AUM) error
	TailnetLockVerifySigningDeeplink(ctx context.Context, url string) (*tka.DeeplinkValidationResult, error)
	TailnetLockWrapPreauthKey(ctx context.Context, preauthKey string, tkaKey key.NLPrivate) (string, error)
	UserDial(ctx context.Context, network, host string, port uint16) (net.Conn, error)
	UserMetrics(ctx context.Context) ([]byte, error)
	UserProfile(ctx context.Context, id tailcfg.UserID) (*tailcfg.UserProfile, error)
	WaitingFiles(ctx context.Context) ([]apitype.WaitingFile, error)
	WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (*local.IPNBusWatcher, error)
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
	WhoIsForIP(ctx context.Context, remoteAddr string, dst netip.Addr) (*apitype.WhoIsResponse, error)
	WhoIsForService(ctx context.Context, remoteAddr string, svcName tailcfg.ServiceName) (*apitype.WhoIsResponse, error)
	WhoIsNodeKey(ctx context.Context, key key.NodePublic) (*apitype.WhoIsResponse, error)
	WhoIsProto(ctx context.Context, proto, remoteAddr string) (*apitype.WhoIsResponse, error)
}

type localClientCtxKey struct{}

// withLocalClient returns a copy of ctx carrying lc, retrievable with
// [localClientFromContext]. It is primarily used by tests to inject a fake.
func withLocalClient(ctx context.Context, lc localClientI) context.Context {
	return context.WithValue(ctx, localClientCtxKey{}, lc)
}

// localClientFromContext returns the [localClientI] stored in ctx by
// [withLocalClient], or the package-level localClient if none was injected.
func localClientFromContext(ctx context.Context) localClientI {
	if lc, ok := ctx.Value(localClientCtxKey{}).(localClientI); ok {
		return lc
	}
	return &localClient
}
