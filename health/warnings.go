// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package health

import (
	"fmt"
	"runtime"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/version"
)

func condRegister(f func() *Warnable) *Warnable {
	if !buildfeatures.HasHealth {
		return nil
	}
	return f()
}

/**
This file contains definitions for the Warnables maintained within this `health` package.
*/

// updateAvailableWarnable is a Warnable that warns the user that an update is available.
var updateAvailableWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "update-available",
		Title:    "Update available",
		Severity: SeverityLow,
		Text: func(args Args) string {
			if version.IsMacAppStore() || version.IsAppleTV() || version.IsMacSys() || version.IsWindowsGUI() || runtime.GOOS == "android" {
				return fmt.Sprintf("An update from version %s to %s is available.", args[ArgCurrentVersion], args[ArgAvailableVersion])
			} else {
				return fmt.Sprintf("An update from version %s to %s is available. Run `tailscale update` or `tailscale set --auto-update` to update now.", args[ArgCurrentVersion], args[ArgAvailableVersion])
			}
		},
	}
})

// securityUpdateAvailableWarnable is a Warnable that warns the user that an important security update is available.
var securityUpdateAvailableWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "security-update-available",
		Title:    "Security update available",
		Severity: SeverityMedium,
		Text: func(args Args) string {
			if version.IsMacAppStore() || version.IsAppleTV() || version.IsMacSys() || version.IsWindowsGUI() || runtime.GOOS == "android" {
				return fmt.Sprintf("A security update from version %s to %s is available.", args[ArgCurrentVersion], args[ArgAvailableVersion])
			} else {
				return fmt.Sprintf("A security update from version %s to %s is available. Run `tailscale update` or `tailscale set --auto-update` to update now.", args[ArgCurrentVersion], args[ArgAvailableVersion])
			}
		},
	}
})

// unstableWarnable is a Warnable that warns the user that they are using an unstable version of Tailscale
// so they won't be surprised by all the issues that may arise.
var unstableWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "is-using-unstable-version",
		Title:    "Using an unstable version",
		Severity: SeverityLow,
		Text:     StaticMessage("This is an unstable version of Tailscale meant for testing and development purposes. Please report any issues to Tailscale."),
	}
})

// NetworkStatusWarnable is a Warnable that warns the user that the network is down.
var NetworkStatusWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:                "network-status",
		Title:               "Network down",
		Severity:            SeverityMedium,
		Text:                StaticMessage("Tailscale cannot connect because the network is down. Check your Internet connection."),
		ImpactsConnectivity: true,
		TimeToVisible:       5 * time.Second,
	}
})

// IPNStateWarnable is a Warnable that warns the user that Tailscale is stopped.
var IPNStateWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "wantrunning-false",
		Title:    "Tailscale off",
		Severity: SeverityLow,
		Text:     StaticMessage("Tailscale is stopped."),
	}
})

// localLogWarnable is a Warnable that warns the user that the local log is misconfigured.
var localLogWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "local-log-config-error",
		Title:    "Local log misconfiguration",
		Severity: SeverityLow,
		Text: func(args Args) string {
			return fmt.Sprintf("The local log is misconfigured: %v", args[ArgError])
		},
	}
})

// LoginStateWarnable is a Warnable that warns the user that they are logged out,
// and provides the last login error if available.
var LoginStateWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "login-state",
		Title:    "Logged out",
		Severity: SeverityMedium,
		Text: func(args Args) string {
			if args[ArgError] != "" {
				return fmt.Sprintf("You are logged out. The last login error was: %v", args[ArgError])
			} else {
				return "You are logged out."
			}
		},
		DependsOn: []*Warnable{IPNStateWarnable},
	}
})

// notInMapPollWarnable is a Warnable that warns the user that we are using a stale network map.
var notInMapPollWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:      "not-in-map-poll",
		Title:     "Out of sync",
		Severity:  SeverityMedium,
		DependsOn: []*Warnable{NetworkStatusWarnable, IPNStateWarnable},
		Text:      StaticMessage("Unable to connect to the Tailscale coordination server to synchronize the state of your tailnet. Peer reachability might degrade over time."),
		// 8 minutes reflects a maximum maintenance window for the coordination server.
		TimeToVisible: 8 * time.Minute,
	}
})

// noDERPHomeWarnable is a Warnable that warns the user that Tailscale doesn't have a home DERP.
var noDERPHomeWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:                "no-derp-home",
		Title:               "No home relay server",
		Severity:            SeverityMedium,
		DependsOn:           []*Warnable{NetworkStatusWarnable},
		Text:                StaticMessage("Tailscale could not connect to any relay server. Check your Internet connection."),
		ImpactsConnectivity: true,
		TimeToVisible:       10 * time.Second,
	}
})

// noDERPConnectionWarnable is a Warnable that warns the user that Tailscale couldn't connect to a specific DERP server.
var noDERPConnectionWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "no-derp-connection",
		Title:    "Relay server unavailable",
		Severity: SeverityMedium,
		DependsOn: []*Warnable{
			NetworkStatusWarnable,

			// Technically noDERPConnectionWarnable could be used to warn about
			// failure to connect to a specific DERP server (e.g. your home is derp1
			// but you're trying to connect to a peer's derp4 and are unable) but as
			// of 2024-09-25 we only use this for connecting to your home DERP, so
			// we depend on noDERPHomeWarnable which is the ability to figure out
			// what your DERP home even is.
			noDERPHomeWarnable,
		},
		Text: func(args Args) string {
			if n := args[ArgDERPRegionName]; n != "" {
				return fmt.Sprintf("Tailscale could not connect to the '%s' relay server. Your Internet connection might be down, or the server might be temporarily unavailable.", n)
			} else {
				return fmt.Sprintf("Tailscale could not connect to the relay server with ID '%s'. Your Internet connection might be down, or the server might be temporarily unavailable.", args[ArgDERPRegionID])
			}
		},
		ImpactsConnectivity: true,
		TimeToVisible:       10 * time.Second,
	}
})

// derpTimeoutWarnable is a Warnable that warns the user that Tailscale hasn't
// heard from the home DERP region for a while.
var derpTimeoutWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "derp-timed-out",
		Title:    "Relay server timed out",
		Severity: SeverityMedium,
		DependsOn: []*Warnable{
			NetworkStatusWarnable,
			noDERPConnectionWarnable, // don't warn about it being stalled if we're not connected
			noDERPHomeWarnable,       // same reason as noDERPConnectionWarnable's dependency
		},
		Text: func(args Args) string {
			if n := args[ArgDERPRegionName]; n != "" {
				return fmt.Sprintf("Tailscale hasn't heard from the '%s' relay server in %v. The server might be temporarily unavailable, or your Internet connection might be down.", n, args[ArgDuration])
			} else {
				return fmt.Sprintf("Tailscale hasn't heard from the home relay server (region ID '%v') in %v. The server might be temporarily unavailable, or your Internet connection might be down.", args[ArgDERPRegionID], args[ArgDuration])
			}
		},
	}
})

// derpRegionErrorWarnable is a Warnable that warns the user that a DERP region is reporting an issue.
var derpRegionErrorWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:      "derp-region-error",
		Title:     "Relay server error",
		Severity:  SeverityLow,
		DependsOn: []*Warnable{NetworkStatusWarnable},
		Text: func(args Args) string {
			return fmt.Sprintf("The relay server #%v is reporting an issue: %v", args[ArgDERPRegionID], args[ArgError])
		},
	}
})

// noUDP4BindWarnable is a Warnable that warns the user that Tailscale couldn't listen for incoming UDP connections.
var noUDP4BindWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:                "no-udp4-bind",
		Title:               "NAT traversal setup failure",
		Severity:            SeverityMedium,
		DependsOn:           []*Warnable{NetworkStatusWarnable, IPNStateWarnable},
		Text:                StaticMessage("Tailscale couldn't listen for incoming UDP connections."),
		ImpactsConnectivity: true,
	}
})

// mapResponseTimeoutWarnable is a Warnable that warns the user that Tailscale hasn't received a network map from the coordination server in a while.
var mapResponseTimeoutWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:      "mapresponse-timeout",
		Title:     "Network map response timeout",
		Severity:  SeverityMedium,
		DependsOn: []*Warnable{NetworkStatusWarnable, IPNStateWarnable},
		Text: func(args Args) string {
			return fmt.Sprintf("Tailscale hasn't received a network map from the coordination server in %s.", args[ArgDuration])
		},
	}
})

// tlsConnectionFailedWarnable is a Warnable that warns the user that Tailscale could not establish an encrypted connection with a server.
var tlsConnectionFailedWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:      "tls-connection-failed",
		Title:     "Encrypted connection failed",
		Severity:  SeverityMedium,
		DependsOn: []*Warnable{NetworkStatusWarnable},
		Text: func(args Args) string {
			return fmt.Sprintf("Tailscale could not establish an encrypted connection with '%q': %v", args[ArgServerName], args[ArgError])
		},
	}
})

// magicsockReceiveFuncWarnable is a Warnable that warns the user that one of the Magicsock functions is not running.
var magicsockReceiveFuncWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "magicsock-receive-func-error",
		Title:    "MagicSock function not running",
		Severity: SeverityMedium,
		Text: func(args Args) string {
			return fmt.Sprintf("The MagicSock function %s is not running. You might experience connectivity issues.", args[ArgMagicsockFunctionName])
		},
	}
})

// testWarnable is a Warnable that is used within this package for testing purposes only.
var testWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "test-warnable",
		Title:    "Test warnable",
		Severity: SeverityLow,
		Text: func(args Args) string {
			return args[ArgError]
		},
	}
})

// applyDiskConfigWarnable is a Warnable that warns the user that there was an error applying the envknob config stored on disk.
var applyDiskConfigWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "apply-disk-config",
		Title:    "Could not apply configuration",
		Severity: SeverityMedium,
		Text: func(args Args) string {
			return fmt.Sprintf("An error occurred applying the Tailscale envknob configuration stored on disk: %v", args[ArgError])
		},
	}
})

// warmingUpWarnableDuration is the duration for which the warmingUpWarnable is reported by the backend after the user
// has changed ipnWantRunning to true from false.
const warmingUpWarnableDuration = 5 * time.Second

// warmingUpWarnable is a Warnable that is reported by the backend when it is starting up, for a maximum time of
// warmingUpWarnableDuration. The GUIs use the presence of this Warnable to prevent showing any other warnings until
// the backend is fully started.
var warmingUpWarnable = condRegister(func() *Warnable {
	return &Warnable{
		Code:     "warming-up",
		Title:    "Tailscale is starting",
		Severity: SeverityLow,
		Text:     StaticMessage("Tailscale is starting. Please wait."),
	}
})
