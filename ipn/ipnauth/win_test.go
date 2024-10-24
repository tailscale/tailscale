// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"testing"

	"tailscale.com/ipn"
)

var (
	winServerEnvs = []WindowsEnvironment{
		{IsServer: true, IsManaged: false},
		{IsServer: true, IsManaged: true},
	}

	winClientEnvs = []WindowsEnvironment{
		{IsServer: false, IsManaged: false},
		{IsServer: false, IsManaged: true},
	}

	winManagedEnvs = []WindowsEnvironment{
		{IsServer: false, IsManaged: true},
		{IsServer: true, IsManaged: true},
	}

	winAllEnvs = []WindowsEnvironment{
		{IsServer: false, IsManaged: false},
		{IsServer: false, IsManaged: true},
		{IsServer: true, IsManaged: false},
		{IsServer: true, IsManaged: true},
	}
)

func TestDeviceAccessWindows(t *testing.T) {
	tests := []struct {
		name          string
		requestAccess []DeviceAccess
		envs          []WindowsEnvironment
		tok           WindowsToken
		wantAllow     bool
	}{
		{
			name:          "allow-all-access-elevated-admin",
			requestAccess: []DeviceAccess{UnrestrictedDeviceAccess},
			envs:          winAllEnvs,
			tok:           &testToken{Admin: true, Elevated: true},
			wantAllow:     true,
		},
		{
			name:          "allow-create-profile-non-elevated-admin",
			requestAccess: []DeviceAccess{CreateProfile},
			envs:          winAllEnvs,
			tok:           &testToken{Admin: true, Elevated: false},
			wantAllow:     true,
		},
		{
			name:          "allow-install-updates-non-elevated-admin",
			requestAccess: []DeviceAccess{InstallUpdates},
			envs:          winAllEnvs,
			tok:           &testToken{Admin: true, Elevated: false},
			wantAllow:     true,
		},
		{
			name:          "deny-privileged-access-non-elevated-admin",
			requestAccess: []DeviceAccess{Debug, DeleteAllProfiles},
			envs:          winAllEnvs,
			tok:           &testToken{Admin: true, Elevated: false},
			wantAllow:     false,
		},

		{
			name:          "allow-read-access-user",
			requestAccess: []DeviceAccess{ReadDeviceStatus, GenerateBugReport},
			envs:          winAllEnvs,
			tok:           &testToken{Admin: false},
			wantAllow:     true,
		},
		{
			name:          "deny-privileged-access-user",
			requestAccess: []DeviceAccess{Debug, DeleteAllProfiles},
			envs:          winAllEnvs,
			tok:           &testToken{Admin: false},
			wantAllow:     false,
		},
		{
			name:          "allow-create-profile-non-server-user",
			requestAccess: []DeviceAccess{CreateProfile},
			envs:          winClientEnvs,
			tok:           &testToken{Admin: false},
			wantAllow:     true,
		},
		{
			name:          "deny-create-profile-server-user",
			requestAccess: []DeviceAccess{CreateProfile},
			envs:          winServerEnvs,
			tok:           &testToken{Admin: false},
			wantAllow:     false,
		},
		{
			name:          "allow-install-updates-non-server-user",
			requestAccess: []DeviceAccess{InstallUpdates},
			envs:          winClientEnvs,
			tok:           &testToken{Admin: false},
			wantAllow:     true,
		},
		{
			name:          "deny-install-updates-server-user",
			requestAccess: []DeviceAccess{InstallUpdates},
			envs:          winServerEnvs,
			tok:           &testToken{Admin: false},
			wantAllow:     false,
		},
	}

	for _, tt := range tests {
		for _, env := range tt.envs {
			user := newWindowsIdentity(tt.tok, env)
			for _, access := range tt.requestAccess {
				testName := tt.name + "-" + env.String() + "-" + access.String()
				t.Run(testName, func(t *testing.T) {
					if res := user.CheckAccess(access); res.Allowed() != tt.wantAllow {
						t.Errorf("got result: %v, want allow: %v", res, tt.wantAllow)
					}
				})
			}
		}
	}
}

func TestProfileAccessWindows(t *testing.T) {
	tests := []struct {
		name          string
		tok           WindowsToken
		profile       ipn.LoginProfile
		prefs         ipn.Prefs
		envs          []WindowsEnvironment
		requestAccess []ProfileAccess
		wantAllow     bool
	}{
		{
			name:          "allow-users-access-to-own-profiles",
			tok:           &testToken{Admin: false, SID: "User1"},
			profile:       ipn.LoginProfile{LocalUserID: "User1"},
			envs:          winAllEnvs,
			requestAccess: []ProfileAccess{UnrestrictedProfileAccess & ^(ServePath)}, // ServePath requires elevated admin rights
			wantAllow:     true,
		},
		{
			name:          "allow-users-disconnect-access-to-others-profiles-on-clients",
			tok:           &testToken{Admin: false, SID: "User1"},
			profile:       ipn.LoginProfile{LocalUserID: "User2"},
			envs:          winClientEnvs,
			requestAccess: []ProfileAccess{Disconnect},
			wantAllow:     true,
		},
		{
			name:          "allow-users-access-to-others-unattended-profiles-on-unmanaged-clients",
			tok:           &testToken{Admin: false, SID: "User1"},
			profile:       ipn.LoginProfile{LocalUserID: "User2"},
			prefs:         ipn.Prefs{ForceDaemon: true},
			envs:          []WindowsEnvironment{{IsServer: false, IsManaged: false}},
			requestAccess: []ProfileAccess{ReadProfileInfo, Connect, Disconnect, ListPeers, ReadPrefs, ChangeExitNode},
			wantAllow:     true,
		},
		{
			name:          "allow-users-read-access-to-others-unattended-profiles-on-managed",
			tok:           &testToken{Admin: false, SID: "User1"},
			profile:       ipn.LoginProfile{LocalUserID: "User2"},
			prefs:         ipn.Prefs{ForceDaemon: true},
			envs:          winManagedEnvs,
			requestAccess: []ProfileAccess{ReadProfileInfo, ListPeers},
			wantAllow:     true,
		},
		{
			name:          "allow-users-read-access-to-others-unattended-profiles-on-servers",
			tok:           &testToken{Admin: false, SID: "User1"},
			profile:       ipn.LoginProfile{LocalUserID: "User2"},
			prefs:         ipn.Prefs{ForceDaemon: true},
			envs:          winServerEnvs,
			requestAccess: []ProfileAccess{ReadProfileInfo, ListPeers},
			wantAllow:     true,
		},
		{
			name:          "deny-users-access-to-non-unattended-others-profiles",
			tok:           &testToken{Admin: false, SID: "User1"},
			profile:       ipn.LoginProfile{LocalUserID: "User2"},
			envs:          winAllEnvs,
			requestAccess: []ProfileAccess{ReadProfileInfo, Connect, ListPeers, ReadPrefs, ChangePrefs, ChangeExitNode},
			wantAllow:     false,
		},
		{
			name:          "allow-elevated-admins-access-to-others-profiles",
			tok:           &testToken{Admin: true, Elevated: true, SID: "Admin1"},
			profile:       ipn.LoginProfile{LocalUserID: "User1"},
			envs:          winAllEnvs,
			requestAccess: []ProfileAccess{UnrestrictedProfileAccess & ^ReadPrivateKeys}, // ReadPrivateKeys is never allowed to others' profiles.
			wantAllow:     true,
		},
		{
			name:          "allow-non-elevated-admins-access-to-shared-profiles",
			tok:           &testToken{Admin: true, Elevated: true, SID: "Admin1"},
			profile:       ipn.LoginProfile{LocalUserID: ""},
			envs:          winManagedEnvs,
			requestAccess: []ProfileAccess{UnrestrictedProfileAccess & ^(ReadPrivateKeys | ServePath)},
			wantAllow:     true,
		},
		{
			name:          "allow-non-elevated-admins-access-to-unattended-profiles",
			tok:           &testToken{Admin: true, Elevated: true, SID: "Admin1"},
			profile:       ipn.LoginProfile{LocalUserID: ""},
			prefs:         ipn.Prefs{ForceDaemon: true},
			envs:          winManagedEnvs,
			requestAccess: []ProfileAccess{UnrestrictedProfileAccess & ^(ReadPrivateKeys | ServePath)},
			wantAllow:     true,
		},
		{
			name:          "deny-non-elevated-admins-access-to-others-profiles",
			tok:           &testToken{Admin: true, Elevated: false, SID: "Admin1"},
			profile:       ipn.LoginProfile{LocalUserID: "User1"},
			envs:          winAllEnvs,
			requestAccess: []ProfileAccess{ReadProfileInfo, Connect, ListPeers, ReadPrefs, ChangePrefs, ChangeExitNode},
			wantAllow:     false,
		},
		{
			name:          "allow-elevated-admins-serve-path-for-own-profiles",
			tok:           &testToken{Admin: true, Elevated: true, SID: "Admin1"},
			profile:       ipn.LoginProfile{LocalUserID: "Admin1"},
			envs:          winAllEnvs,
			requestAccess: []ProfileAccess{ServePath},
			wantAllow:     true,
		},
		{
			name:          "deny-non-elevated-admins-serve-path-for-own-profiles",
			tok:           &testToken{Admin: true, Elevated: false, SID: "Admin1"},
			profile:       ipn.LoginProfile{LocalUserID: "Admin1"},
			envs:          winAllEnvs,
			requestAccess: []ProfileAccess{ServePath},
			wantAllow:     false,
		},
	}

	for _, tt := range tests {
		for _, env := range tt.envs {
			user := newWindowsIdentity(tt.tok, env)
			for _, access := range tt.requestAccess {
				testName := tt.name + "-" + env.String() + "-" + access.String()
				t.Run(testName, func(t *testing.T) {
					res := user.CheckProfileAccess(tt.profile.View(), ipn.PrefsGetterFor(tt.prefs.View()), access)
					if res.Allowed() != tt.wantAllow {
						t.Errorf("got result: %v, want allow: %v", res, tt.wantAllow)
					}
				})
			}
		}
	}
}
