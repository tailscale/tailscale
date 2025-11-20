// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package captivedetection provides a way to detect if the system is connected to a network that has
// a captive portal. It does this by making HTTP requests to known captive portal detection endpoints
// and checking if the HTTP responses indicate that a captive portal might be present.
package captivedetection

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// Detector checks whether the system is behind a captive portal.
type Detector struct {
	clock func() time.Time

	// httpClient is the HTTP client that is used for captive portal detection. It is configured
	// to not follow redirects, have a short timeout and no keep-alive.
	httpClient *http.Client
	// currIfIndex is the index of the interface that is currently being used by the httpClient.
	currIfIndex int
	// mu guards currIfIndex.
	mu syncs.Mutex
	// logf is the logger used for logging messages. If it is nil, log.Printf is used.
	logf logger.Logf
}

// NewDetector creates a new Detector instance for captive portal detection.
func NewDetector(logf logger.Logf) *Detector {
	d := &Detector{logf: logf}
	d.httpClient = &http.Client{
		// No redirects allowed
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:       d.dialContext,
			DisableKeepAlives: true,
		},
		Timeout: Timeout,
	}
	return d
}

func (d *Detector) Now() time.Time {
	if d.clock != nil {
		return d.clock()
	}
	return time.Now()
}

// Timeout is the timeout for captive portal detection requests. Because the captive portal intercepting our requests
// is usually located on the LAN, this is a relatively short timeout.
const Timeout = 3 * time.Second

// Detect is the entry point to the API. It attempts to detect if the system is behind a captive portal
// by making HTTP requests to known captive portal detection Endpoints. If any of the requests return a response code
// or body that looks like a captive portal, Detect returns true. It returns false in all other cases, including when any
// error occurs during a detection attempt.
//
// This function might take a while to return, as it will attempt to detect a captive portal on all available interfaces
// by performing multiple HTTP requests. It should be called in a separate goroutine if you want to avoid blocking.
func (d *Detector) Detect(ctx context.Context, netMon *netmon.Monitor, derpMap *tailcfg.DERPMap, preferredDERPRegionID int) (found bool) {
	return d.detectCaptivePortalWithGOOS(ctx, netMon, derpMap, preferredDERPRegionID, runtime.GOOS)
}

func (d *Detector) detectCaptivePortalWithGOOS(ctx context.Context, netMon *netmon.Monitor, derpMap *tailcfg.DERPMap, preferredDERPRegionID int, goos string) (found bool) {
	ifState := netMon.InterfaceState()
	if !ifState.AnyInterfaceUp() {
		d.logf("[v2] DetectCaptivePortal: no interfaces up, returning false")
		return false
	}

	endpoints := availableEndpoints(derpMap, preferredDERPRegionID, d.logf, goos)

	// Here we try detecting a captive portal using *all* available interfaces on the system
	// that have a IPv4 address. We consider to have found a captive portal when any interface
	// reports one may exists. This is necessary because most systems have multiple interfaces,
	// and most importantly on macOS no default route interface is set until the user has accepted
	// the captive portal alert thrown by the system. If no default route interface is known,
	// we need to try with anything that might remotely resemble a Wi-Fi interface.
	for ifName, i := range ifState.Interface {
		if !i.IsUp() || i.IsLoopback() || interfaceNameDoesNotNeedCaptiveDetection(ifName, goos) {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			d.logf("[v1] DetectCaptivePortal: failed to get addresses for interface %s: %v", ifName, err)
			continue
		}
		if len(addrs) == 0 {
			continue
		}
		d.logf("[v2] attempting to do captive portal detection on interface %s", ifName)
		res := d.detectOnInterface(ctx, i.Index, endpoints)
		if res {
			d.logf("DetectCaptivePortal(found=true,ifName=%s)", ifName)
			return true
		}
	}

	d.logf("DetectCaptivePortal(found=false)")
	return false
}

// interfaceNameDoesNotNeedCaptiveDetection returns true if an interface does not require captive portal detection
// based on its name. This is useful to avoid making unnecessary HTTP requests on interfaces that are known to not
// require it. We also avoid making requests on the interface prefixes "pdp" and "rmnet", which are cellular data
// interfaces on iOS and Android, respectively, and would be needlessly battery-draining.
func interfaceNameDoesNotNeedCaptiveDetection(ifName string, goos string) bool {
	ifName = strings.ToLower(ifName)
	excludedPrefixes := []string{"tailscale", "tun", "tap", "docker", "kube", "wg", "ipsec"}
	if goos == "windows" {
		excludedPrefixes = append(excludedPrefixes, "loopback", "tunnel", "ppp", "isatap", "teredo", "6to4")
	} else if goos == "darwin" || goos == "ios" {
		excludedPrefixes = append(excludedPrefixes, "pdp", "awdl", "bridge", "ap", "utun", "tap", "llw", "anpi", "lo", "stf", "gif", "xhc", "pktap")
	} else if goos == "android" {
		excludedPrefixes = append(excludedPrefixes, "rmnet", "p2p", "dummy", "sit")
	}
	for _, prefix := range excludedPrefixes {
		if strings.HasPrefix(ifName, prefix) {
			return true
		}
	}
	return false
}

// detectOnInterface reports whether or not we think the system is behind a
// captive portal, detected by making a request to a URL that we know should
// return a "204 No Content" response and checking if that's what we get.
//
// The boolean return is whether we think we have a captive portal.
func (d *Detector) detectOnInterface(ctx context.Context, ifIndex int, endpoints []Endpoint) bool {
	defer d.httpClient.CloseIdleConnections()

	use := min(len(endpoints), 5)
	endpoints = endpoints[:use]
	d.logf("[v2] %d available captive portal detection endpoints; trying %v", len(endpoints), use)

	// We try to detect the captive portal more quickly by making requests to multiple endpoints concurrently.
	var wg sync.WaitGroup
	resultCh := make(chan bool, len(endpoints))

	// Once any goroutine detects a captive portal, we shut down the others.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, e := range endpoints {
		wg.Add(1)
		go func(endpoint Endpoint) {
			defer wg.Done()
			found, err := d.verifyCaptivePortalEndpoint(ctx, endpoint, ifIndex)
			if err != nil {
				if ctx.Err() == nil {
					d.logf("[v1] checkCaptivePortalEndpoint failed with endpoint %v: %v", endpoint, err)
				}
				return
			}
			if found {
				cancel() // one match is good enough
				resultCh <- true
			}
		}(e)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for result := range resultCh {
		if result {
			// If any of the endpoints seems to be a captive portal, we consider the system to be behind one.
			return true
		}
	}

	return false
}

// verifyCaptivePortalEndpoint checks if the given Endpoint is a captive portal by making an HTTP request to the
// given Endpoint URL using the interface with index ifIndex, and checking if the response looks like a captive portal.
func (d *Detector) verifyCaptivePortalEndpoint(ctx context.Context, e Endpoint, ifIndex int) (found bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	u := *e.URL
	v := u.Query()
	v.Add("t", strconv.Itoa(int(d.Now().Unix())))
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate, no-transform, max-age=0")

	// Attach the Tailscale challenge header if the endpoint supports it. Not all captive portal detection endpoints
	// support this, so we only attach it if the endpoint does.
	if e.SupportsTailscaleChallenge {
		// Note: the set of valid characters in a challenge and the total
		// length is limited; see isChallengeChar in cmd/derper for more
		// details.
		chal := "ts_" + e.URL.Host
		req.Header.Set("X-Tailscale-Challenge", chal)
	}

	d.mu.Lock()
	d.currIfIndex = ifIndex
	d.mu.Unlock()

	// Make the actual request, and check if the response looks like a captive portal or not.
	r, err := d.httpClient.Do(req)
	if err != nil {
		return false, err
	}

	return e.responseLooksLikeCaptive(r, d.logf), nil
}

func (d *Detector) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	ifIndex := d.currIfIndex

	dl := &net.Dialer{
		Timeout: Timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketInterfaceIndex(c, ifIndex, d.logf)
		},
	}

	return dl.DialContext(ctx, network, addr)
}
