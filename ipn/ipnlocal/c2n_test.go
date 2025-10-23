// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"cmp"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/filter/filtertype"

	gcmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestHandleC2NTLSCertStatus(t *testing.T) {
	b := &LocalBackend{
		store:   &mem.Store{},
		varRoot: t.TempDir(),
	}
	certDir, err := b.certDir()
	if err != nil {
		t.Fatalf("certDir error: %v", err)
	}
	if _, err := b.getCertStore(); err != nil {
		t.Fatalf("getCertStore error: %v", err)
	}

	testRoot, err := certTestFS.ReadFile("testdata/rootCA.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(testRoot) {
		t.Fatal("Unable to add test CA to the cert pool")
	}
	testX509Roots = roots
	defer func() { testX509Roots = nil }()

	tests := []struct {
		name       string
		domain     string
		copyFile   bool   // copy testdata/example.com.pem to the certDir
		wantStatus int    // 0 means 200
		wantError  string // wanted non-JSON non-200 error
		now        time.Time
		want       *tailcfg.C2NTLSCertInfo
	}{
		{
			name:       "no domain",
			wantStatus: 400,
			wantError:  "no 'domain'\n",
		},
		{
			name:   "missing",
			domain: "example.com",
			want: &tailcfg.C2NTLSCertInfo{
				Error:   "no certificate",
				Missing: true,
			},
		},
		{
			name:     "valid",
			domain:   "example.com",
			now:      time.Date(2023, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			want: &tailcfg.C2NTLSCertInfo{
				Valid:     true,
				NotBefore: "2023-02-07T20:34:18Z",
				NotAfter:  "2025-05-07T19:34:18Z",
			},
		},
		{
			name:     "expired",
			domain:   "example.com",
			now:      time.Date(2030, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			want: &tailcfg.C2NTLSCertInfo{
				Error:   "cert expired",
				Expired: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.RemoveAll(certDir) // reset per test
			if tt.copyFile {
				os.MkdirAll(certDir, 0755)
				if err := os.WriteFile(filepath.Join(certDir, "example.com.crt"),
					must.Get(os.ReadFile("testdata/example.com.pem")), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(certDir, "example.com.key"),
					must.Get(os.ReadFile("testdata/example.com-key.pem")), 0644); err != nil {
					t.Fatal(err)
				}
			}
			b.clock = tstest.NewClock(tstest.ClockOpts{
				Start: tt.now,
			})

			rec := httptest.NewRecorder()
			handleC2NTLSCertStatus(b, rec, httptest.NewRequest("GET", "/tls-cert-status?domain="+url.QueryEscape(tt.domain), nil))
			res := rec.Result()
			wantStatus := cmp.Or(tt.wantStatus, 200)
			if res.StatusCode != wantStatus {
				t.Fatalf("status code = %v; want %v. Body: %s", res.Status, wantStatus, rec.Body.Bytes())
			}
			if wantStatus == 200 {
				var got tailcfg.C2NTLSCertInfo
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatalf("bad JSON: %v", err)
				}
				if !reflect.DeepEqual(&got, tt.want) {
					t.Errorf("got %v; want %v", logger.AsJSON(got), logger.AsJSON(tt.want))
				}
			} else if tt.wantError != "" {
				if got := rec.Body.String(); got != tt.wantError {
					t.Errorf("body = %q; want %q", got, tt.wantError)
				}
			}
		})
	}

}

// eachStructField calls cb for each struct field in struct type tp, recursively.
func eachStructField(tp reflect.Type, cb func(reflect.Type, reflect.StructField)) {
	if !strings.HasPrefix(tp.PkgPath(), "tailscale.com/") {
		// Stop traversing when we reach a non-tailscale type.
		return
	}

	for i := range tp.NumField() {
		cb(tp, tp.Field(i))

		switch tp.Field(i).Type.Kind() {
		case reflect.Struct:
			eachStructField(tp.Field(i).Type, cb)
		case reflect.Slice, reflect.Array, reflect.Ptr, reflect.Map:
			if tp.Field(i).Type.Elem().Kind() == reflect.Struct {
				eachStructField(tp.Field(i).Type.Elem(), cb)
			}
		}
	}
}

// eachStructValue calls cb for each struct field in the struct value v, recursively.
func eachStructValue(v reflect.Value, cb func(reflect.Type, reflect.StructField, reflect.Value)) {
	if v.IsZero() {
		return
	}

	for i := range v.NumField() {
		cb(v.Type(), v.Type().Field(i), v.Field(i))

		switch v.Type().Field(i).Type.Kind() {
		case reflect.Struct:
			eachStructValue(v.Field(i), cb)
		case reflect.Slice, reflect.Array, reflect.Ptr, reflect.Map:
			if v.Field(i).Type().Elem().Kind() == reflect.Struct {
				eachStructValue(v.Field(i).Addr().Elem(), cb)
			}
		}
	}
}

// TestRedactNetmapPrivateKeys tests that redactNetmapPrivateKeys redacts all private keys
// and other private fields from a netmap.NetworkMap, and only those fields.
func TestRedactNetmapPrivateKeys(t *testing.T) {
	type field struct {
		t reflect.Type
		f string
	}
	f := func(t any, f string) field {
		return field{reflect.TypeOf(t), f}
	}
	// fields is a map of all struct fields in netmap.NetworkMap and its
	// sub-structs, marking each field as private (true) or public (false).
	// If you add a new field to netmap.NetworkMap or its sub-structs,
	// you must add it to this list, marking it as private or public.
	fields := map[field]bool{
		// Private fields to be redacted.
		f(netmap.NetworkMap{}, "PrivateKey"): true,

		// All other fields are public.
		f(netmap.NetworkMap{}, "AllCaps"):                  false,
		f(netmap.NetworkMap{}, "CollectServices"):          false,
		f(netmap.NetworkMap{}, "DERPMap"):                  false,
		f(netmap.NetworkMap{}, "DNS"):                      false,
		f(netmap.NetworkMap{}, "DisplayMessages"):          false,
		f(netmap.NetworkMap{}, "Domain"):                   false,
		f(netmap.NetworkMap{}, "DomainAuditLogID"):         false,
		f(netmap.NetworkMap{}, "Expiry"):                   false,
		f(netmap.NetworkMap{}, "MachineKey"):               false,
		f(netmap.NetworkMap{}, "Name"):                     false,
		f(netmap.NetworkMap{}, "NodeKey"):                  false,
		f(netmap.NetworkMap{}, "PacketFilter"):             false,
		f(netmap.NetworkMap{}, "PacketFilterRules"):        false,
		f(netmap.NetworkMap{}, "Peers"):                    false,
		f(netmap.NetworkMap{}, "SSHPolicy"):                false,
		f(netmap.NetworkMap{}, "SelfNode"):                 false,
		f(netmap.NetworkMap{}, "TKAEnabled"):               false,
		f(netmap.NetworkMap{}, "TKAHead"):                  false,
		f(netmap.NetworkMap{}, "UserProfiles"):             false,
		f(filtertype.CapMatch{}, "Cap"):                    false,
		f(filtertype.CapMatch{}, "Dst"):                    false,
		f(filtertype.CapMatch{}, "Values"):                 false,
		f(filtertype.Match{}, "Caps"):                      false,
		f(filtertype.Match{}, "Dsts"):                      false,
		f(filtertype.Match{}, "IPProto"):                   false,
		f(filtertype.Match{}, "SrcCaps"):                   false,
		f(filtertype.Match{}, "Srcs"):                      false,
		f(filtertype.Match{}, "SrcsContains"):              false,
		f(filtertype.NetPortRange{}, "Net"):                false,
		f(filtertype.NetPortRange{}, "Ports"):              false,
		f(filtertype.PortRange{}, "First"):                 false,
		f(filtertype.PortRange{}, "Last"):                  false,
		f(key.DiscoPublic{}, "k"):                          false,
		f(key.MachinePublic{}, "k"):                        false,
		f(key.NodePrivate{}, "_"):                          false,
		f(key.NodePrivate{}, "k"):                          false,
		f(key.NodePublic{}, "k"):                           false,
		f(tailcfg.CapGrant{}, "CapMap"):                    false,
		f(tailcfg.CapGrant{}, "Caps"):                      false,
		f(tailcfg.CapGrant{}, "Dsts"):                      false,
		f(tailcfg.DERPHomeParams{}, "RegionScore"):         false,
		f(tailcfg.DERPMap{}, "HomeParams"):                 false,
		f(tailcfg.DERPMap{}, "OmitDefaultRegions"):         false,
		f(tailcfg.DERPMap{}, "Regions"):                    false,
		f(tailcfg.DNSConfig{}, "CertDomains"):              false,
		f(tailcfg.DNSConfig{}, "Domains"):                  false,
		f(tailcfg.DNSConfig{}, "ExitNodeFilteredSet"):      false,
		f(tailcfg.DNSConfig{}, "ExtraRecords"):             false,
		f(tailcfg.DNSConfig{}, "FallbackResolvers"):        false,
		f(tailcfg.DNSConfig{}, "Nameservers"):              false,
		f(tailcfg.DNSConfig{}, "Proxied"):                  false,
		f(tailcfg.DNSConfig{}, "Resolvers"):                false,
		f(tailcfg.DNSConfig{}, "Routes"):                   false,
		f(tailcfg.DNSConfig{}, "TempCorpIssue13969"):       false,
		f(tailcfg.DNSRecord{}, "Name"):                     false,
		f(tailcfg.DNSRecord{}, "Type"):                     false,
		f(tailcfg.DNSRecord{}, "Value"):                    false,
		f(tailcfg.DisplayMessageAction{}, "Label"):         false,
		f(tailcfg.DisplayMessageAction{}, "URL"):           false,
		f(tailcfg.DisplayMessage{}, "ImpactsConnectivity"): false,
		f(tailcfg.DisplayMessage{}, "PrimaryAction"):       false,
		f(tailcfg.DisplayMessage{}, "Severity"):            false,
		f(tailcfg.DisplayMessage{}, "Text"):                false,
		f(tailcfg.DisplayMessage{}, "Title"):               false,
		f(tailcfg.FilterRule{}, "CapGrant"):                false,
		f(tailcfg.FilterRule{}, "DstPorts"):                false,
		f(tailcfg.FilterRule{}, "IPProto"):                 false,
		f(tailcfg.FilterRule{}, "SrcBits"):                 false,
		f(tailcfg.FilterRule{}, "SrcIPs"):                  false,
		f(tailcfg.HostinfoView{}, "ж"):                     false,
		f(tailcfg.Hostinfo{}, "AllowsUpdate"):              false,
		f(tailcfg.Hostinfo{}, "App"):                       false,
		f(tailcfg.Hostinfo{}, "AppConnector"):              false,
		f(tailcfg.Hostinfo{}, "BackendLogID"):              false,
		f(tailcfg.Hostinfo{}, "Cloud"):                     false,
		f(tailcfg.Hostinfo{}, "Container"):                 false,
		f(tailcfg.Hostinfo{}, "Desktop"):                   false,
		f(tailcfg.Hostinfo{}, "DeviceModel"):               false,
		f(tailcfg.Hostinfo{}, "Distro"):                    false,
		f(tailcfg.Hostinfo{}, "DistroCodeName"):            false,
		f(tailcfg.Hostinfo{}, "DistroVersion"):             false,
		f(tailcfg.Hostinfo{}, "Env"):                       false,
		f(tailcfg.Hostinfo{}, "ExitNodeID"):                false,
		f(tailcfg.Hostinfo{}, "FrontendLogID"):             false,
		f(tailcfg.Hostinfo{}, "GoArch"):                    false,
		f(tailcfg.Hostinfo{}, "GoArchVar"):                 false,
		f(tailcfg.Hostinfo{}, "GoVersion"):                 false,
		f(tailcfg.Hostinfo{}, "Hostname"):                  false,
		f(tailcfg.Hostinfo{}, "IPNVersion"):                false,
		f(tailcfg.Hostinfo{}, "IngressEnabled"):            false,
		f(tailcfg.Hostinfo{}, "Location"):                  false,
		f(tailcfg.Hostinfo{}, "Machine"):                   false,
		f(tailcfg.Hostinfo{}, "NetInfo"):                   false,
		f(tailcfg.Hostinfo{}, "NoLogsNoSupport"):           false,
		f(tailcfg.Hostinfo{}, "OS"):                        false,
		f(tailcfg.Hostinfo{}, "OSVersion"):                 false,
		f(tailcfg.Hostinfo{}, "Package"):                   false,
		f(tailcfg.Hostinfo{}, "PushDeviceToken"):           false,
		f(tailcfg.Hostinfo{}, "RequestTags"):               false,
		f(tailcfg.Hostinfo{}, "RoutableIPs"):               false,
		f(tailcfg.Hostinfo{}, "SSH_HostKeys"):              false,
		f(tailcfg.Hostinfo{}, "Services"):                  false,
		f(tailcfg.Hostinfo{}, "ServicesHash"):              false,
		f(tailcfg.Hostinfo{}, "ShareeNode"):                false,
		f(tailcfg.Hostinfo{}, "ShieldsUp"):                 false,
		f(tailcfg.Hostinfo{}, "StateEncrypted"):            false,
		f(tailcfg.Hostinfo{}, "TPM"):                       false,
		f(tailcfg.Hostinfo{}, "Userspace"):                 false,
		f(tailcfg.Hostinfo{}, "UserspaceRouter"):           false,
		f(tailcfg.Hostinfo{}, "WireIngress"):               false,
		f(tailcfg.Hostinfo{}, "WoLMACs"):                   false,
		f(tailcfg.Location{}, "City"):                      false,
		f(tailcfg.Location{}, "CityCode"):                  false,
		f(tailcfg.Location{}, "Country"):                   false,
		f(tailcfg.Location{}, "CountryCode"):               false,
		f(tailcfg.Location{}, "Latitude"):                  false,
		f(tailcfg.Location{}, "Longitude"):                 false,
		f(tailcfg.Location{}, "Priority"):                  false,
		f(tailcfg.NetInfo{}, "DERPLatency"):                false,
		f(tailcfg.NetInfo{}, "FirewallMode"):               false,
		f(tailcfg.NetInfo{}, "HairPinning"):                false,
		f(tailcfg.NetInfo{}, "HavePortMap"):                false,
		f(tailcfg.NetInfo{}, "LinkType"):                   false,
		f(tailcfg.NetInfo{}, "MappingVariesByDestIP"):      false,
		f(tailcfg.NetInfo{}, "OSHasIPv6"):                  false,
		f(tailcfg.NetInfo{}, "PCP"):                        false,
		f(tailcfg.NetInfo{}, "PMP"):                        false,
		f(tailcfg.NetInfo{}, "PreferredDERP"):              false,
		f(tailcfg.NetInfo{}, "UPnP"):                       false,
		f(tailcfg.NetInfo{}, "WorkingICMPv4"):              false,
		f(tailcfg.NetInfo{}, "WorkingIPv6"):                false,
		f(tailcfg.NetInfo{}, "WorkingUDP"):                 false,
		f(tailcfg.NetPortRange{}, "Bits"):                  false,
		f(tailcfg.NetPortRange{}, "IP"):                    false,
		f(tailcfg.NetPortRange{}, "Ports"):                 false,
		f(tailcfg.NetPortRange{}, "_"):                     false,
		f(tailcfg.NodeView{}, "ж"):                         false,
		f(tailcfg.Node{}, "Addresses"):                     false,
		f(tailcfg.Node{}, "AllowedIPs"):                    false,
		f(tailcfg.Node{}, "Cap"):                           false,
		f(tailcfg.Node{}, "CapMap"):                        false,
		f(tailcfg.Node{}, "Capabilities"):                  false,
		f(tailcfg.Node{}, "ComputedName"):                  false,
		f(tailcfg.Node{}, "ComputedNameWithHost"):          false,
		f(tailcfg.Node{}, "Created"):                       false,
		f(tailcfg.Node{}, "DataPlaneAuditLogID"):           false,
		f(tailcfg.Node{}, "DiscoKey"):                      false,
		f(tailcfg.Node{}, "Endpoints"):                     false,
		f(tailcfg.Node{}, "ExitNodeDNSResolvers"):          false,
		f(tailcfg.Node{}, "Expired"):                       false,
		f(tailcfg.Node{}, "HomeDERP"):                      false,
		f(tailcfg.Node{}, "Hostinfo"):                      false,
		f(tailcfg.Node{}, "ID"):                            false,
		f(tailcfg.Node{}, "IsJailed"):                      false,
		f(tailcfg.Node{}, "IsWireGuardOnly"):               false,
		f(tailcfg.Node{}, "Key"):                           false,
		f(tailcfg.Node{}, "KeyExpiry"):                     false,
		f(tailcfg.Node{}, "KeySignature"):                  false,
		f(tailcfg.Node{}, "LastSeen"):                      false,
		f(tailcfg.Node{}, "LegacyDERPString"):              false,
		f(tailcfg.Node{}, "Machine"):                       false,
		f(tailcfg.Node{}, "MachineAuthorized"):             false,
		f(tailcfg.Node{}, "Name"):                          false,
		f(tailcfg.Node{}, "Online"):                        false,
		f(tailcfg.Node{}, "PrimaryRoutes"):                 false,
		f(tailcfg.Node{}, "SelfNodeV4MasqAddrForThisPeer"): false,
		f(tailcfg.Node{}, "SelfNodeV6MasqAddrForThisPeer"): false,
		f(tailcfg.Node{}, "Sharer"):                        false,
		f(tailcfg.Node{}, "StableID"):                      false,
		f(tailcfg.Node{}, "Tags"):                          false,
		f(tailcfg.Node{}, "UnsignedPeerAPIOnly"):           false,
		f(tailcfg.Node{}, "User"):                          false,
		f(tailcfg.Node{}, "computedHostIfDifferent"):       false,
		f(tailcfg.PortRange{}, "First"):                    false,
		f(tailcfg.PortRange{}, "Last"):                     false,
		f(tailcfg.SSHPolicy{}, "Rules"):                    false,
		f(tailcfg.Service{}, "Description"):                false,
		f(tailcfg.Service{}, "Port"):                       false,
		f(tailcfg.Service{}, "Proto"):                      false,
		f(tailcfg.Service{}, "_"):                          false,
		f(tailcfg.TPMInfo{}, "FamilyIndicator"):            false,
		f(tailcfg.TPMInfo{}, "FirmwareVersion"):            false,
		f(tailcfg.TPMInfo{}, "Manufacturer"):               false,
		f(tailcfg.TPMInfo{}, "Model"):                      false,
		f(tailcfg.TPMInfo{}, "SpecRevision"):               false,
		f(tailcfg.TPMInfo{}, "Vendor"):                     false,
		f(tailcfg.UserProfileView{}, "ж"):                  false,
		f(tailcfg.UserProfile{}, "DisplayName"):            false,
		f(tailcfg.UserProfile{}, "ID"):                     false,
		f(tailcfg.UserProfile{}, "LoginName"):              false,
		f(tailcfg.UserProfile{}, "ProfilePicURL"):          false,
		f(views.Slice[ipproto.Proto]{}, "ж"):               false,
		f(views.Slice[tailcfg.FilterRule]{}, "ж"):          false,
	}

	t.Run("field_list_is_complete", func(t *testing.T) {
		seen := set.Set[field]{}
		eachStructField(reflect.TypeOf(netmap.NetworkMap{}), func(rt reflect.Type, sf reflect.StructField) {
			f := field{rt, sf.Name}
			seen.Add(f)
			if _, ok := fields[f]; !ok {
				// Fail the test if netmap has a field not in the list. If you see this test
				// failure, please add the new field to the fields map above, marking it as private or public.
				t.Errorf("netmap field has not been declared as private or public: %v.%v", rt, sf.Name)
			}
		})

		for want := range fields {
			if !seen.Contains(want) {
				// Fail the test if the list has a field not in netmap. If you see this test
				// failure, please remove the field from the fields map above.
				t.Errorf("field declared that has not been found in netmap: %v.%v", want.t, want.f)
			}
		}
	})

	// tests is a list of test cases, each with a non-redacted netmap and the expected redacted netmap.
	// If you add a new private field to netmap.NetworkMap or its sub-structs, please add a test case
	// here that has that field set in nm, and the expected redacted value in wantRedacted.
	tests := []struct {
		name         string
		nm           *netmap.NetworkMap
		wantRedacted *netmap.NetworkMap
	}{
		{
			name: "redact_private_key",
			nm: &netmap.NetworkMap{
				PrivateKey: key.NewNode(),
			},
			wantRedacted: &netmap.NetworkMap{},
		},
	}

	// confirmedRedacted is a set of all private fields that have been covered by the tests above.
	confirmedRedacted := set.Set[field]{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Record which of the private fields are set in the non-redacted netmap.
			eachStructValue(reflect.ValueOf(tt.nm).Elem(), func(tt reflect.Type, sf reflect.StructField, v reflect.Value) {
				f := field{tt, sf.Name}
				if shouldRedact := fields[f]; shouldRedact && !v.IsZero() {
					confirmedRedacted.Add(f)
				}
			})

			got, _ := redactNetmapPrivateKeys(tt.nm)
			if !reflect.DeepEqual(got, tt.wantRedacted) {
				t.Errorf("unexpected redacted netmap: %+v", got)
			}

			// Check that all private fields in the redacted netmap are zero.
			eachStructValue(reflect.ValueOf(got).Elem(), func(tt reflect.Type, sf reflect.StructField, v reflect.Value) {
				f := field{tt, sf.Name}
				if shouldRedact := fields[f]; shouldRedact && !v.IsZero() {
					t.Errorf("field not redacted: %v.%v", tt, sf.Name)
				}
			})
		})
	}

	// Check that all private fields in netmap.NetworkMap and its sub-structs
	// are covered by the tests above. If you see a test failure here,
	// please add a test case above that has that field set in nm.
	for f, shouldRedact := range fields {
		if shouldRedact {
			if !confirmedRedacted.Contains(f) {
				t.Errorf("field not covered by tests: %v.%v", f.t, f.f)
			}
		}
	}
}

func TestHandleC2NDebugNetmap(t *testing.T) {
	nm := &netmap.NetworkMap{
		Name: "myhost",
		SelfNode: (&tailcfg.Node{
			ID:       100,
			Name:     "myhost",
			StableID: "deadbeef",
			Key:      key.NewNode().Public(),
			Hostinfo: (&tailcfg.Hostinfo{Hostname: "myhost"}).View(),
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:       101,
				Name:     "peer1",
				StableID: "deadbeef",
				Key:      key.NewNode().Public(),
				Hostinfo: (&tailcfg.Hostinfo{Hostname: "peer1"}).View(),
			}).View(),
		},
		PrivateKey: key.NewNode(),
	}
	withoutPrivateKey := *nm
	withoutPrivateKey.PrivateKey = key.NodePrivate{}

	for _, tt := range []struct {
		name string
		req  *tailcfg.C2NDebugNetmapRequest
		want *netmap.NetworkMap
	}{
		{
			name: "simple_get",
			want: &withoutPrivateKey,
		},
		{
			name: "post_no_omit",
			req:  &tailcfg.C2NDebugNetmapRequest{},
			want: &withoutPrivateKey,
		},
		{
			name: "post_omit_peers_and_name",
			req:  &tailcfg.C2NDebugNetmapRequest{OmitFields: []string{"Peers", "Name"}},
			want: &netmap.NetworkMap{
				SelfNode: nm.SelfNode,
			},
		},
		{
			name: "post_omit_nonexistent_field",
			req:  &tailcfg.C2NDebugNetmapRequest{OmitFields: []string{"ThisFieldDoesNotExist"}},
			want: &withoutPrivateKey,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestLocalBackend(t)
			b.currentNode().SetNetMap(nm)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/debug/netmap", nil)
			if tt.req != nil {
				b, err := json.Marshal(tt.req)
				if err != nil {
					t.Fatalf("json.Marshal: %v", err)
				}
				req = httptest.NewRequest("POST", "/debug/netmap", bytes.NewReader(b))
			}
			handleC2NDebugNetMap(b, rec, req)
			res := rec.Result()
			wantStatus := 200
			if res.StatusCode != wantStatus {
				t.Fatalf("status code = %v; want %v. Body: %s", res.Status, wantStatus, rec.Body.Bytes())
			}
			var resp tailcfg.C2NDebugNetmapResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("bad JSON: %v", err)
			}
			got := &netmap.NetworkMap{}
			if err := json.Unmarshal(resp.Current, got); err != nil {
				t.Fatalf("bad JSON: %v", err)
			}

			if diff := gcmp.Diff(tt.want, got,
				gcmp.AllowUnexported(netmap.NetworkMap{}, key.NodePublic{}, views.Slice[tailcfg.FilterRule]{}),
				cmpopts.EquateComparable(key.MachinePublic{}),
			); diff != "" {
				t.Errorf("netmap mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
